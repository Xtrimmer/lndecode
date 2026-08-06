// BOLT 12 conformance tests over the spec vectors in test/vectors/.

const { test, describe } = require('node:test');
const assert = require('node:assert');

const { load } = require('./load.js');
const FORMAT_VECTORS = require('./vectors/format-string.json');

const lndecode = load();

describe('bolt12 string format', () => {
    for (const { comment, valid, string } of FORMAT_VECTORS) {
        test(`${valid ? 'accepts' : 'rejects'}: ${comment}`, () => {
            if (valid) {
                assert.doesNotThrow(() => lndecode.bolt12ToBytes(string));
            } else {
                assert.throws(() => lndecode.bolt12ToBytes(string));
            }
        });
    }

    test('all valid vectors unpack to the same bytes', () => {
        const unpacked = new Set(
            FORMAT_VECTORS.filter(v => v.valid)
                .map(v => lndecode.byteArrayToHexString(lndecode.bolt12ToBytes(v.string).bytes))
        );
        assert.strictEqual(unpacked.size, 1, `expected one distinct payload, got ${unpacked.size}`);
    });

    test('prefix is read as lno', () => {
        for (const v of FORMAT_VECTORS.filter(v => v.valid)) {
            assert.strictEqual(lndecode.bolt12ToBytes(v.string).prefix, 'lno', v.comment);
        }
    });
});

describe('bolt12 continuation rules', () => {
    const cases = [
        ['leading +', '+lno1pqps'],
        ['trailing +', 'lno1pqps+'],
        ['trailing + with whitespace', 'lno1pqps+ '],
        ['doubled +', 'ln++o1pqps'],
        ["+ after a non-bech32 character", 'lno+1pqps']
    ];
    for (const [name, input] of cases) {
        test(`rejects ${name}`, () => {
            assert.throws(() => lndecode.normalizeBolt12(input), /surrounded by bech32/i);
        });
    }

    test('joins across whitespace, including newlines', () => {
        assert.strictEqual(lndecode.normalizeBolt12('lno1pq+  \r\n ps'), 'lno1pqps');
    });

    test('rejects mixed case before looking at continuations', () => {
        assert.throws(() => lndecode.normalizeBolt12('LnO1pqps'), /mixed case/i);
    });
});

describe('bolt12 has no checksum', () => {
    test('all characters contribute to the payload', () => {
        const full = FORMAT_VECTORS.find(v => v.valid && !v.string.includes('+')).string;
        const truncated = full.slice(0, -6);
        const a = lndecode.byteArrayToHexString(lndecode.bolt12ToBytes(full).bytes);
        let b;
        try {
            b = lndecode.byteArrayToHexString(lndecode.bolt12ToBytes(truncated).bytes);
        } catch (e) {
            b = `rejected: ${e.message}`;
        }
        assert.notStrictEqual(a, b);
    });
});
