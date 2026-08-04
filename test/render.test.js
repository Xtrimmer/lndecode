// Display-model tests for both request forms.

const { test, describe } = require('node:test');
const assert = require('node:assert');

const { load } = require('./load.js');
const OFFER_VECTORS = require('./vectors/offers.json');
const { VALID_VECTORS } = require('./vectors.js');

const lndecode = load();

function offerModel(substring) {
    const found = OFFER_VECTORS.find(v => v.description.includes(substring));
    assert.ok(found, `no vector matching "${substring}"`);
    return lndecode.decodeRequest(found.bolt12);
}

function rows(model) {
    const out = new Map();
    for (const row of model.sections[0].rows) out.set(row.label, row);
    return out;
}

describe('dispatch', () => {
    test('routes an invoice to the bolt11 model', () => {
        const model = lndecode.decodeRequest(VALID_VECTORS[0].invoice);
        assert.strictEqual(model.kind, 'bolt11-invoice');
    });

    test('routes an offer to the offer model', () => {
        assert.strictEqual(offerModel('Minimal bolt12 offer').kind, 'bolt12-offer');
    });

    test('reports the signed bolt12 forms as unsupported', () => {
        for (const prefix of ['lnr', 'lnp']) {
            assert.throws(() => lndecode.decodeRequest(prefix + '1qqq'), /not yet supported/i);
        }
    });

    test('rejects an unknown prefix', () => {
        assert.throws(() => lndecode.decodeRequest('lnzz1qqq'), /unknown prefix/i);
    });
});

describe('offer model', () => {
    test('every valid offer builds a model with rows', () => {
        for (const v of OFFER_VECTORS.filter(v => v.valid)) {
            const model = lndecode.decodeRequest(v.bolt12);
            assert.strictEqual(model.sections.length, 1);
            assert.ok(model.sections[0].rows.length > 0, v.description);
        }
    });

    test('an absent offer_chains shows bitcoin mainnet', () => {
        assert.strictEqual(rows(offerModel('Minimal bolt12 offer')).get('Chains').value, 'bitcoin mainnet');
    });

    test('known chain hashes are named, in encoded order', () => {
        assert.strictEqual(rows(offerModel('for bitcoin or liquidv1')).get('Chains').value,
            'liquidv1, bitcoin mainnet');
        assert.strictEqual(rows(offerModel('for testnet')).get('Chains').value, 'bitcoin testnet');
    });

    test('an absent amount reads as any amount', () => {
        assert.strictEqual(rows(offerModel('Minimal bolt12 offer')).get('Amount').value, 'any amount');
    });

    test('a bitcoin amount is shown in millisatoshi', () => {
        assert.strictEqual(rows(offerModel('with amount')).get('Amount').value, '10000 msat');
    });

    // 10000 USD here is 100.00 dollars. The offer does not carry the ISO 4217 exponent,
    // so the value is labelled rather than converted.
    test('a currency amount is labelled as minor units', () => {
        assert.strictEqual(rows(offerModel('with currency')).get('Amount').value,
            '10000 USD (minor units)');
    });

    test('expiry is shown as a date', () => {
        assert.match(rows(offerModel('with expiry')).get('Expires').value, /2034|2035/);
    });

    test('a zero quantity max reads as unlimited', () => {
        assert.strictEqual(rows(offerModel('with unlimited (or unknown) quantity')).get('Quantity Max').value,
            'unlimited');
        assert.strictEqual(rows(offerModel('with quantity')).get('Quantity Max').value, '5');
    });

    test('feature bits are listed by number', () => {
        assert.strictEqual(rows(offerModel('with feature')).get('Feature Bits').value, '99');
    });

    test('a blinded path becomes nested rows', () => {
        const row = rows(offerModel('blinded path via Bob')).get('Blinded Path 1');
        assert.ok(row.sub, 'should be a nested row');
        const labels = row.sub.map(s => s.label);
        assert.deepStrictEqual(Array.from(labels),
            ['First Node Id', 'Path Key', 'Hop 1 Blinded Id', 'Hop 2 Blinded Id']);
    });

    test('a sciddir first node id is spelled out', () => {
        const row = rows(offerModel('first_node_id using sciddir')).get('Blinded Path 1');
        assert.strictEqual(row.sub[0].value, 'short channel id 000000000000002a, direction 0');
    });

    test('two paths become two rows', () => {
        const built = rows(offerModel('second blinded path via 1x2x3'));
        assert.ok(built.has('Blinded Path 1'));
        assert.ok(built.has('Blinded Path 2'));
    });

    test('no signature or checksum row appears', () => {
        for (const v of OFFER_VECTORS.filter(v => v.valid)) {
            const labels = lndecode.decodeRequest(v.bolt12).sections[0].rows.map(r => r.label);
            for (const absent of ['Signature', 'Checksum', 'Date', 'Signing Data']) {
                assert.ok(!labels.includes(absent), `${v.description} should have no ${absent} row`);
            }
        }
    });
});
