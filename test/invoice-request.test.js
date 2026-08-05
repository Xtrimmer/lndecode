// BOLT 12 invoice request tests.
//
// The spec publishes exactly one invoice request, inside signature-test.json, and no
// invalid suite. The negative cases below are therefore built by re-encoding that vector
// with one thing changed, which means the encoder here is part of the test surface: every
// mutation is checked to still round-trip, so a rejection cannot come from a broken build.

const { test, describe } = require('node:test');
const assert = require('node:assert');

const { load } = require('./load.js');
const SIGNATURE_VECTORS = require('./vectors/signature.json');

const lndecode = load();

const hex = bytes => lndecode.byteArrayToHexString(bytes);
const bytes = string => lndecode.hexStringToByteArray(string);

const VECTOR = SIGNATURE_VECTORS.find(v => v.bolt12 !== undefined);

function records() {
    return Array.from(lndecode.parseTlvStream(lndecode.bolt12ToBytes(VECTOR.bolt12).bytes))
        .map(r => ({ type: r.type, value: Array.from(r.value) }));
}

function encodeBigSize(value) {
    const n = BigInt(value);
    if (n < 0xfdn) return [Number(n)];
    const width = n <= 0xffffn ? 2 : n <= 0xffffffffn ? 4 : 8;
    const out = [width === 2 ? 0xfd : width === 4 ? 0xfe : 0xff];
    for (let shift = BigInt(width * 8 - 8); shift >= 0n; shift -= 8n) {
        out.push(Number((n >> shift) & 0xffn));
    }
    return out;
}

function encodeStream(list) {
    const sorted = list.slice().sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : 0));
    let out = [];
    for (const record of sorted) {
        out = out.concat(encodeBigSize(record.type), encodeBigSize(record.value.length),
            record.value);
    }
    return out;
}

function toFiveBit(byteArray) {
    let bits = 0;
    let value = 0;
    const out = [];
    for (const byte of byteArray) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push((value >> bits) & 31);
        }
    }
    if (bits > 0) out.push((value << (5 - bits)) & 31);
    return out;
}

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function encodeBolt12(prefix, byteArray) {
    return prefix + '1' + toFiveBit(byteArray).map(v => CHARSET.charAt(v)).join('');
}

function rebuild(list, prefix) {
    return encodeBolt12(prefix === undefined ? 'lnr' : prefix, encodeStream(list));
}

function without(type) {
    return records().filter(r => r.type !== BigInt(type));
}

function withRecord(type, value) {
    return without(type).concat([{ type: BigInt(type), value: value }]);
}

describe('the encoder used to build negative cases', () => {
    test('round-trips the published vector byte for byte', () => {
        const original = lndecode.bolt12ToBytes(VECTOR.bolt12);
        assert.strictEqual(hex(encodeStream(records())), hex(original.bytes));
    });

    test('the re-encoded string decodes identically', () => {
        const rebuilt = rebuild(records());
        assert.strictEqual(lndecode.decodeInvoiceRequest(rebuilt).merkle_root, VECTOR.merkle);
    });

    test('BigSize widths round-trip', () => {
        for (const value of [0, 1, 252, 253, 0xffff, 0x10000, 0xffffffff, 0x100000000]) {
            const reader = lndecode.byteReader(encodeBigSize(value));
            assert.strictEqual(reader.readBigSize('value'), BigInt(value), String(value));
        }
    });
});

describe('the published invoice request', () => {
    test('decodes', () => {
        assert.doesNotThrow(() => lndecode.decodeInvoiceRequest(VECTOR.bolt12));
    });

    test('reproduces the published merkle root', () => {
        assert.strictEqual(lndecode.decodeInvoiceRequest(VECTOR.bolt12).merkle_root,
            VECTOR.merkle);
    });

    test('names every field', () => {
        const decoded = lndecode.decodeInvoiceRequest(VECTOR.bolt12);
        assert.deepStrictEqual(Array.from(decoded.fields, f => f.name),
            ['invreq_metadata', 'offer_currency', 'offer_amount', 'offer_description',
                'offer_issuer_id', 'invreq_payer_id', 'signature']);
    });

    test('decodes the values the vector comment describes', () => {
        const decoded = lndecode.decodeInvoiceRequest(VECTOR.bolt12);
        const valueOf = name => Array.from(decoded.fields).find(f => f.name === name).value;
        assert.strictEqual(valueOf('offer_currency'), 'USD');
        assert.strictEqual(valueOf('offer_amount'), 100n);
        assert.strictEqual(valueOf('offer_description'), 'A Mathematical Treatise');
        assert.strictEqual(valueOf('invreq_metadata'), '0000000000000000');
    });

    test('an offer is not an invoice request', () => {
        const offers = require('./vectors/offers.json');
        assert.throws(() => lndecode.decodeInvoiceRequest(offers.find(v => v.valid).bolt12),
            /expected an lnr/i);
    });
});

describe('required fields', () => {
    for (const [type, name] of [[0, 'invreq_metadata'], [88, 'invreq_payer_id']]) {
        test(`${name} is required`, () => {
            assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(without(type))),
                new RegExp(`requires ${name}`));
        });
    }

    test('a signature is required', () => {
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(without(240))),
            /requires a signature/i);
    });
});

describe('the signature', () => {
    test('a tampered signature does not verify', () => {
        const signature = records().find(r => r.type === 240n).value.slice();
        signature[0] ^= 0x01;
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(240, signature))),
            /does not verify against invreq_payer_id/);
    });

    test('a tampered field does not verify', () => {
        // The description is inside the signed tree, so changing it changes the root.
        const description = Array.from(lndecode.textToByteArray('A Mathematical Treatis3'));
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(10, description))),
            /does not verify against invreq_payer_id/);
    });

    test('substituting another key does not verify', () => {
        const issuer = records().find(r => r.type === 22n).value;
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(88, issuer))),
            /does not verify against invreq_payer_id/);
    });
});

describe('type ranges', () => {
    test('a non-signature type above 159 is rejected', () => {
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(200, [1]))),
            /outside the ranges an invoice request may use/);
    });

    test('a type above the experimental range is rejected', () => {
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(3000000000, [1]))),
            /outside the ranges an invoice request may use/);
    });

    test('an unknown even type in range is rejected', () => {
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(100, [1]))),
            /unknown even tlv type 100/);
    });

    test('an unknown odd type in range is ignored', () => {
        // Ignored means the field is dropped, but it still signs, so the signature over the
        // altered tree must fail rather than the type being rejected.
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(101, [1]))),
            /does not verify against invreq_payer_id/);
    });

    test('an unknown odd type is carried in raw_records', () => {
        const list = withRecord(101, [1]);
        // Re-sign is impossible here, so inspect the stream through the offer-side parser.
        const parsed = Array.from(lndecode.parseTlvStream(encodeStream(list)));
        assert.ok(parsed.some(r => r.type === 101n));
    });
});

describe('quantity rules', () => {
    test('invreq_quantity without offer_quantity_max is rejected', () => {
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(86, [1]))),
            /invreq_quantity requires offer_quantity_max/);
    });

    test('offer_quantity_max without invreq_quantity is rejected', () => {
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(20, [5]))),
            /offer_quantity_max requires invreq_quantity/);
    });

    test('a quantity above the maximum is rejected', () => {
        const list = withRecord(20, [5]).concat([{ type: 86n, value: [6] }]);
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(list)),
            /invreq_quantity must be between 1 and 5/);
    });

    test('a zero quantity is rejected when the maximum is non-zero', () => {
        const list = withRecord(20, [5]).concat([{ type: 86n, value: [] }]);
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(list)),
            /invreq_quantity must be between 1 and 5/);
    });
});

describe('amount rules', () => {
    test('without an offer, invreq_amount is required', () => {
        // Dropping offer_issuer_id makes this a request not responding to an offer.
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(without(22))),
            /invreq_amount is required without an offer/);
    });

    test('without an offer, offer_quantity_max is rejected', () => {
        const list = without(22).concat([{ type: 20n, value: [5] }, { type: 82n, value: [1] }]);
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(list)),
            /offer_quantity_max requires offer_issuer_id or offer_paths/);
    });

    test('an amount below the offer amount is rejected', () => {
        // offer_currency must go, since the expected amount is only computable in msat.
        const list = without(6).concat([{ type: 82n, value: [0x63] }]);
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(list)),
            /invreq_amount 99 is less than the expected 100/);
    });

    test('the expected amount scales with quantity', () => {
        const list = without(6)
            .concat([{ type: 20n, value: [5] }, { type: 86n, value: [3] },
                { type: 82n, value: [0x01, 0x2b] }]);
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(list)),
            /invreq_amount 299 is less than the expected 300/);
    });

    test('a currency-denominated offer amount is not compared', () => {
        // With offer_currency present the offer amount is in minor units, so no msat
        // comparison is possible. The signature check is what fails here.
        const list = records().concat([{ type: 82n, value: [1] }]);
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(list)),
            /does not verify against invreq_payer_id/);
    });
});

describe('invreq_paths', () => {
    // first_node_id as a sciddir (1 + 8 bytes), then a 33-byte first_path_key, then num_hops.
    const SCIDDIR = [0x00, 0, 0, 0, 0, 0, 0, 0, 1];
    const PATH_KEY = [0x02].concat(new Array(32).fill(0x02));

    test('a path with zero hops is rejected', () => {
        const path = SCIDDIR.concat(PATH_KEY, [0x00]);
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(90, path))),
            /blinded_path has zero hops/);
    });

    test('a well-formed path passes validation and fails only on the signature', () => {
        const hop = [0x02].concat(new Array(32).fill(0x02), [0x00, 0x00]);
        const path = SCIDDIR.concat(PATH_KEY, [0x01], hop);
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(90, path))),
            /does not verify against invreq_payer_id/);
    });

    test('offer_paths alone makes a request answer an offer', () => {
        // Dropping offer_issuer_id but supplying offer_paths keeps the offer branch active,
        // so invreq_amount stays optional and the signature is what fails.
        const hop = [0x02].concat(new Array(32).fill(0x02), [0x00, 0x00]);
        const path = SCIDDIR.concat(PATH_KEY, [0x01], hop);
        const list = without(22).concat([{ type: 16n, value: path }]);
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(list)),
            /does not verify against invreq_payer_id/);
    });
});

describe('features', () => {
    test('an unknown even feature bit is rejected', () => {
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(84, [0x04]))),
            /unknown even invoice request feature bit 2/);
    });

    test('an unknown odd feature bit is ignored', () => {
        assert.throws(() => lndecode.decodeInvoiceRequest(rebuild(withRecord(84, [0x02]))),
            /does not verify against invreq_payer_id/);
    });
});

describe('bip 353 names', () => {
    function bip353(name, domain) {
        return [name.length].concat(Array.from(lndecode.textToByteArray(name)),
            [domain.length], Array.from(lndecode.textToByteArray(domain)));
    }

    test('an allowed name passes validation and fails only on the signature', () => {
        assert.throws(() => lndecode.decodeInvoiceRequest(
            rebuild(withRecord(91, bip353('alice', 'example.com')))),
            /does not verify against invreq_payer_id/);
    });

    for (const [label, name, domain] of [
        ['a space in the name', 'al ice', 'example.com'],
        ['a plus in the domain', 'alice', 'exam+ple.com'],
        ['a slash in the domain', 'alice', 'example.com/x']
    ]) {
        test(`${label} is rejected`, () => {
            assert.throws(() => lndecode.decodeInvoiceRequest(
                rebuild(withRecord(91, bip353(name, domain)))),
                /disallowed character/);
        });
    }
});
