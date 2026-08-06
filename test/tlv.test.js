// BigSize and TLV stream tests over BOLT 1 Appendix A and the BOLT 12 offer vectors.
//
// Hex literals below are split at the boundary between a BigSize prefix and its value, or
// between one tlv record and the next.
/* eslint-disable no-useless-concat */

const { test, describe } = require('node:test');
const assert = require('node:assert');

const { load } = require('./load.js');
const BIGSIZE_VECTORS = require('./vectors/bigsize.json');
const OFFER_VECTORS = require('./vectors/offers.json');

const lndecode = load();

function reader(hex) {
    return lndecode.byteReader(lndecode.hexStringToByteArray(hex));
}

describe('BigSize', () => {
    for (const vector of BIGSIZE_VECTORS) {
        const label = vector.name || `bytes ${vector.bytes || '(empty)'}`;
        if (vector.exp_error) {
            test(`rejects ${label} (${vector.exp_error})`, () => {
                assert.throws(() => reader(vector.bytes).readBigSize('value'));
            });
        } else {
            test(`reads ${label} as ${vector.value}`, () => {
                const r = reader(vector.bytes);
                assert.strictEqual(r.readBigSize('value'), BigInt(vector.value));
                assert.strictEqual(r.remaining(), 0, 'should consume the whole encoding');
            });
        }
    }

    test('reads 2^64-1 exactly', () => {
        // 0xff prefix, then eight bytes.
        assert.strictEqual(reader('ff' + 'ffffffffffffffff').readBigSize('value'), 18446744073709551615n);
    });

    test('rejects a non-canonical encoding of a small value', () => {
        assert.throws(() => reader('fd00fc').readBigSize('value'), /minimally encoded/i);
    });
});

describe('TLV stream', () => {
    test('reads records in order', () => {
        // type 1 length 1 value 00, then type 2 length 2 value 0102
        const records = lndecode.parseTlvStream(lndecode.hexStringToByteArray('010100' + '02020102'));
        assert.strictEqual(records.length, 2);
        assert.strictEqual(records[0].type, 1n);
        assert.strictEqual(records[1].length, 2);
        assert.strictEqual(lndecode.byteArrayToHexString(records[1].value), '0102');
    });

    test('an empty stream yields no records', () => {
        assert.strictEqual(lndecode.parseTlvStream([]).length, 0);
    });

    test('rejects a length beyond the end of the stream', () => {
        assert.throws(() => lndecode.parseTlvStream(lndecode.hexStringToByteArray('0105' + '0000')),
            /exceeds the bytes remaining/i);
    });

    test('rejects types that do not strictly increase', () => {
        assert.throws(() => lndecode.parseTlvStream(lndecode.hexStringToByteArray('020100' + '010100')),
            /strictly increase/i);
    });

    test('rejects a duplicated type', () => {
        assert.throws(() => lndecode.parseTlvStream(lndecode.hexStringToByteArray('010100' + '010100')),
            /strictly increase/i);
    });

    test('rejects a non-minimal type', () => {
        assert.throws(() => lndecode.parseTlvStream(lndecode.hexStringToByteArray('fd0001' + '0100')),
            /minimally encoded/i);
    });

    test('ignores an unknown odd type but rejects an unknown even one', () => {
        const known = new Set([2n]);
        const odd = lndecode.parseTlvStream(lndecode.hexStringToByteArray('030100'));
        assert.doesNotThrow(() => lndecode.requireUnderstoodTypes(odd, known));

        const even = lndecode.parseTlvStream(lndecode.hexStringToByteArray('040100'));
        assert.throws(() => lndecode.requireUnderstoodTypes(even, known), /unknown even tlv type 4/i);
    });
});

describe('offer TLV framing', () => {
    for (const vector of OFFER_VECTORS.filter(v => v.valid && v.fields)) {
        test(`frames: ${vector.description}`, () => {
            const records = lndecode.parseOfferTlvStream(vector.bolt12).records;
            assert.strictEqual(records.length, vector.fields.length, 'record count');
            records.forEach((record, i) => {
                const expected = vector.fields[i];
                assert.strictEqual(Number(record.type), expected.type, 'type');
                assert.strictEqual(record.length, expected.length, `type ${expected.type} length`);
                assert.strictEqual(lndecode.byteArrayToHexString(record.value), expected.hex,
                    `type ${expected.type} value`);
            });
        });
    }
});

describe('offer vectors rejected at the stream layer', () => {
    // Vectors that fail on framing or type rules alone.
    const STREAM_LEVEL = [
        'Malformed: fields out of order',
        'Malformed: unknown even TLV type 78',
        'Malformed: empty',
        'Malformed: truncated at type',
        'Malformed: truncated in length',
        'Malformed: truncated after length',
        'Malformed: truncated in description',
        'Contains type >= 80',
        'Contains type > 1999999999',
        'Contains unknown even type (1000000002)',
        'Bech32 padding exceeds 4-bit limit'
    ];
    for (const description of STREAM_LEVEL) {
        test(`rejects: ${description}`, () => {
            const vector = OFFER_VECTORS.find(v => v.description === description);
            assert.ok(vector, `vector "${description}" should exist`);
            assert.strictEqual(vector.valid, false, 'vector should be an invalid one');
            assert.throws(() => lndecode.parseOfferTlvStream(vector.bolt12));
        });
    }

    // Vectors labelled as blinded-path problems whose offer_paths record is framed with
    // a length too small to hold a blinded_path, so the stream fails to parse first.
    const REJECTED_BEFORE_BLINDED_PATH = [
        'Malformed: zero num_hops in blinded_path',
        'Malformed: truncated onionmsg_hop in blinded_path',
        'Malformed: bad first_node_id in blinded_path',
        'Malformed: bad path_key in blinded_path',
        'Malformed: bad blinded_node_id in onionmsg_hop'
    ];
    for (const description of REJECTED_BEFORE_BLINDED_PATH) {
        test(`rejects before blinded-path decoding: ${description}`, () => {
            const vector = OFFER_VECTORS.find(v => v.description === description);
            assert.ok(vector, `vector "${description}" should exist`);
            assert.throws(() => lndecode.parseOfferTlvStream(vector.bolt12));
        });
    }
});
