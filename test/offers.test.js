// Offer field decoding tests over the vectors in test/vectors/offers.json.

const { test, describe } = require('node:test');
const assert = require('node:assert');

const { load } = require('./load.js');
const OFFER_VECTORS = require('./vectors/offers.json');

const lndecode = load();

function vector(substring) {
    const found = OFFER_VECTORS.find(v => v.description.includes(substring));
    assert.ok(found, `no vector matching "${substring}"`);
    return found;
}

function decode(substring) {
    return lndecode.decodeOffer(vector(substring).bolt12);
}

function field(decoded, name) {
    const found = decoded.fields.find(f => f.name === name);
    assert.ok(found, `expected a ${name} field, got ${decoded.fields.map(f => f.name).join(', ')}`);
    return found.value;
}

describe('every valid offer decodes', () => {
    for (const v of OFFER_VECTORS.filter(v => v.valid)) {
        test(v.description, () => {
            const decoded = lndecode.decodeOffer(v.bolt12);
            assert.strictEqual(decoded.prefix, 'lno');
            assert.ok(decoded.fields.length > 0, 'should decode at least one field');
        });
    }
});

describe('offer field values', () => {
    test('description', () => {
        assert.strictEqual(field(decode('with description (but no amount)'), 'offer_description'),
            'Test vectors');
    });

    test('amount in millisatoshi', () => {
        assert.strictEqual(field(decode('with amount'), 'offer_amount'), 10000n);
    });

    test('currency and amount together', () => {
        const decoded = decode('with currency');
        assert.strictEqual(field(decoded, 'offer_currency'), 'USD');
        assert.strictEqual(field(decoded, 'offer_amount'), 10000n);
    });

    test('absolute expiry', () => {
        assert.strictEqual(field(decode('with expiry'), 'offer_absolute_expiry'), 2051184600n);
    });

    test('issuer', () => {
        assert.strictEqual(field(decode('with issuer'), 'offer_issuer'),
            'https://bolt12.org BOLT12 industries');
    });

    test('quantity max', () => {
        assert.strictEqual(field(decode('with quantity'), 'offer_quantity_max'), 5n);
        assert.strictEqual(field(decode('with unlimited (or unknown) quantity'), 'offer_quantity_max'), 0n);
        assert.strictEqual(field(decode('with single quantity'), 'offer_quantity_max'), 1n);
    });

    test('metadata is 16 zero bytes', () => {
        assert.strictEqual(field(decode('with metadata'), 'offer_metadata'), '00'.repeat(16));
    });

    test('issuer id is a compressed point', () => {
        const point = field(decode('Minimal bolt12 offer'), 'offer_issuer_id');
        assert.strictEqual(point.length, 66);
        assert.match(point, /^0[23]/);
    });
});

describe('offer chains', () => {
    test('a single chain', () => {
        assert.strictEqual(field(decode('for testnet'), 'offer_chains').length, 1);
    });

    test('two chains, in encoded order', () => {
        assert.deepStrictEqual(Array.from(field(decode('for bitcoin or liquidv1'), 'offer_chains')), [
            '1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003',
            '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000'
        ]);
    });
});

describe('offer features', () => {
    test('sets exactly bit 99', () => {
        const hex = field(decode('with feature'), 'offer_features');
        const bytes = lndecode.hexStringToByteArray(hex);
        const set = [];
        for (let bit = 0; bit < bytes.length * 8; bit++) {
            if ((bytes[bytes.length - 1 - (bit >> 3)] >> (bit % 8)) & 1) set.push(bit);
        }
        assert.deepStrictEqual(set, [99]);
    });
});

describe('blinded paths', () => {
    test('two hops with their encrypted data', () => {
        const paths = field(decode('blinded path via Bob'), 'offer_paths');
        assert.strictEqual(paths.length, 1);
        assert.strictEqual(paths[0].path.length, 2);
        assert.strictEqual(paths[0].path[0].encrypted_recipient_data, '00'.repeat(16));
        assert.strictEqual(paths[0].path[1].encrypted_recipient_data, '11'.repeat(8));
    });

    test('a first_node_id given as a short channel id and direction', () => {
        const paths = field(decode('first_node_id using sciddir'), 'offer_paths');
        assert.strictEqual(paths[0].first_node_id.direction, 0);
        assert.strictEqual(paths[0].first_node_id.short_channel_id, '000000000000002a');
    });

    test('two paths, one keyed by point and one by sciddir', () => {
        const paths = field(decode('second blinded path via 1x2x3'), 'offer_paths');
        assert.strictEqual(paths.length, 2);
        assert.match(paths[0].first_node_id.node_id, /^0[23]/);
        assert.strictEqual(paths[1].first_node_id.direction, 1);
        assert.strictEqual(paths[1].first_node_id.short_channel_id, '0000010000020003');
    });

    test('an offer with paths and no issuer id decodes', () => {
        const decoded = decode('with no issuer_id and blinded path');
        assert.strictEqual(field(decoded, 'offer_paths').length, 1);
        assert.strictEqual(decoded.fields.find(f => f.name === 'offer_issuer_id'), undefined);
    });
});

describe('unknown fields', () => {
    test('an unknown odd type is left out of the decoded fields', () => {
        assert.deepStrictEqual(Array.from(decode('unknown odd field').fields.map(f => f.name)),
            ['offer_description', 'offer_issuer_id']);
    });
});

describe('offer vectors rejected while decoding fields', () => {
    const FIELD_LEVEL = [
        'Malformed: invalid offer_chains length',
        'offer_chains with zero entries',
        'Malformed: truncated currency UTF-8',
        'Malformed: invalid currency UTF-8',
        'Malformed: truncated description UTF-8',
        'Malformed: invalid description UTF-8',
        'Malformed: truncated issuer UTF-8',
        'Malformed: invalid issuer UTF-8',
        'Malformed: truncated offer_paths',
        'Second offer_path is empty'
    ];
    for (const description of FIELD_LEVEL) {
        test(`rejects: ${description}`, () => {
            const v = vector(description);
            assert.strictEqual(v.valid, false);
            assert.throws(() => lndecode.decodeOffer(v.bolt12));
        });
    }
});

describe('offer semantic rules', () => {
    const SEMANTIC = [
        ['Contains unknown feature 122', /unknown even offer feature bit 122/i],
        ['Missing offer_description, but has offer_amount', /requires offer_description/i],
        ['Missing offer_amount with offer_currency', /offer_currency requires offer_amount/i],
        ['Invalid: zero offer_amount', /greater than zero/i],
        ['Invalid: zero offer_amount with currency', /greater than zero/i],
        ['Missing offer_issuer_id and no offer_path', /requires offer_issuer_id or offer_paths/i]
    ];
    for (const [description, expected] of SEMANTIC) {
        test(`rejects: ${description}`, () => {
            const v = vector(description);
            assert.strictEqual(v.valid, false);
            assert.throws(() => lndecode.decodeOffer(v.bolt12), expected);
        });
    }

    test('an odd feature bit is still ignored', () => {
        assert.doesNotThrow(() => decode('with feature'));
    });

    test('a type outside the offer ranges is rejected', () => {
        // type 80 with an empty value, then a valid issuer id
        const records = lndecode.parseTlvStream(lndecode.hexStringToByteArray('5000'));
        assert.throws(() => lndecode.requireOfferTypeRanges(records), /outside the ranges/i);

        const inRange = lndecode.parseTlvStream(lndecode.hexStringToByteArray('2100'));
        assert.doesNotThrow(() => lndecode.requireOfferTypeRanges(inRange));
    });
});

describe('offer vector coverage', () => {
    test('every valid vector decodes and every invalid one is rejected', () => {
        const accepted = [];
        for (const v of OFFER_VECTORS.filter(v => !v.valid)) {
            try {
                lndecode.decodeOffer(v.bolt12);
                accepted.push(v.description);
            } catch { /* expected */ }
        }
        assert.deepStrictEqual(accepted, [], 'every invalid vector should be rejected');

        for (const v of OFFER_VECTORS.filter(v => v.valid)) {
            assert.doesNotThrow(() => lndecode.decodeOffer(v.bolt12), v.description);
        }
    });

    // 33 bytes with a valid 0x02 prefix, so only the curve check rejects it.
    test('rejects: Malformed: invalid offer_issuer_id', () => {
        assert.throws(() => lndecode.decodeOffer(vector('invalid offer_issuer_id').bolt12),
            /not a point on the secp256k1 curve/i);
    });
});
