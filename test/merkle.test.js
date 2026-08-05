// BOLT 12 merkle tree and tagged hash tests.
//
// Every published intermediate is asserted, not just the root: a wrong nonce input or a
// wrong branch order still yields a plausible 32-byte root.

const { test, describe } = require('node:test');
const assert = require('node:assert');

const { load } = require('./load.js');
const VECTORS = require('./vectors/signature.json');

const lndecode = load();

const hex = bytes => lndecode.byteArrayToHexString(bytes);
const bytes = string => lndecode.hexStringToByteArray(string);

// The vector keys carry their own inputs, so the expected values are read out of the key
// names rather than restated here. For example:
//   "H(`LnLeaf`,010203e8)": "67a2a995..."
//   "H(`LnBranch`,19d6ecfa...b013756c...)": "c3774abb..."
function keyed(entry, pattern) {
    for (const [key, value] of Object.entries(entry)) {
        const match = key.match(pattern);
        if (match) return { argument: match[1], value: value };
    }
    return undefined;
}

function leafOf(leaf) {
    const found = keyed(leaf, /^H\(`LnLeaf`,([0-9a-f]+)\)$/);
    assert.ok(found, `no LnLeaf key in ${JSON.stringify(Object.keys(leaf))}`);
    return found;
}

function nonceOf(leaf) {
    const found = keyed(leaf, /^H\(`LnNonce`\|first-tlv,(.+)\)$/);
    assert.ok(found, 'no LnNonce key');
    return found;
}

function nodeOf(leaf) {
    const found = keyed(leaf, /^H\(`LnBranch`,(leaf\+nonce)\)$/);
    assert.ok(found, 'no LnBranch key on the leaf');
    return found;
}

function branchOf(branch) {
    const found = keyed(branch, /^H\(`LnBranch`,([0-9a-f]{128})\)$/);
    assert.ok(found, `no LnBranch key in ${JSON.stringify(Object.keys(branch))}`);
    return found;
}

// The nodes above the base level that came from a pairing. An odd final node is carried
// up unchanged and is not a new hash, so it is not counted twice.
function computedBranches(levels) {
    const out = [];
    for (let i = 0; i + 1 < levels.length; i++) {
        const pairings = Math.floor(levels[i].length / 2);
        for (let j = 0; j < pairings; j++) out.push(hex(levels[i + 1][j]));
    }
    return out;
}

describe('tagged hashes', () => {
    test('H(tag, msg) is SHA256(SHA256(tag) || SHA256(tag) || msg)', () => {
        const tag = lndecode.textToByteArray('LnLeaf');
        const msg = bytes('010203e8');
        const tagHash = lndecode.sha256(tag);
        assert.strictEqual(hex(lndecode.bolt12TaggedHash(tag, msg)),
            hex(lndecode.sha256(tagHash.concat(tagHash).concat(msg))));
    });

    test('the tag is hashed twice, not once', () => {
        // Hashing the tag a single time is the obvious mistake and still returns 32 bytes.
        const tag = lndecode.textToByteArray('LnLeaf');
        const msg = bytes('010203e8');
        const single = lndecode.sha256(lndecode.sha256(tag).concat(msg));
        assert.notStrictEqual(hex(lndecode.bolt12TaggedHash(tag, msg)), hex(single));
    });
});

describe('tlv type bytes', () => {
    // The nonce leaf hashes the type field, whose width is the leading BigSize's.
    const CASES = [
        ['010203e8', '01'],
        ['00080000000000000000', '00'],
        ['58210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c', '58'],
        ['fd00fd0100', 'fd00fd'],
        ['fe000100000100', 'fe00010000'],
        ['ff00000001000000000100', 'ff0000000100000000']
    ];
    for (const [tlv, expected] of CASES) {
        test(`${tlv.slice(0, 12)} has type bytes ${expected}`, () => {
            assert.strictEqual(hex(lndecode.tlvTypeBytes(bytes(tlv))), expected);
        });
    }

    test('an empty record is an error', () => {
        assert.throws(() => lndecode.tlvTypeBytes([]), /empty tlv record/i);
    });

    test('a type wider than the record is an error', () => {
        assert.throws(() => lndecode.tlvTypeBytes(bytes('ff0000')), /truncated tlv type/i);
    });
});

describe('branch ordering', () => {
    const LOW = bytes('19d6ecfa3be88d29c30e56167f58526d7695dfac9cb95e1256deb222c92db4d0');
    const HIGH = bytes('b013756c8fee86503a0b4abdab4cddeb1af5d344ca6fc2fa8b6c08938caa6f93');

    test('inputs are ordered by value, not by position', () => {
        assert.strictEqual(hex(lndecode.branchNode(LOW, HIGH)), hex(lndecode.branchNode(HIGH, LOW)));
    });

    test('the lesser hash goes first', () => {
        assert.strictEqual(hex(lndecode.branchNode(HIGH, LOW)),
            hex(lndecode.bolt12TaggedHash(lndecode.textToByteArray('LnBranch'), LOW.concat(HIGH))));
    });
});

describe('published merkle vectors', () => {
    test('there are four', () => {
        assert.strictEqual(VECTORS.length, 4);
    });

    for (const [index, vector] of VECTORS.entries()) {
        const label = `[${index}] ${vector.tlv}, ${vector.leaves.length} record(s)`;
        const tlvs = vector.leaves.map(leaf => bytes(leafOf(leaf).argument));
        const firstTlv = bytes(vector['first-tlv']);

        test(`${label}: first-tlv is the first record's own bytes`, () => {
            assert.strictEqual(hex(firstTlv), hex(tlvs[0]));
        });

        test(`${label}: every leaf hash`, () => {
            for (const [at, leaf] of vector.leaves.entries()) {
                const expected = leafOf(leaf);
                assert.strictEqual(hex(lndecode.leafHash(bytes(expected.argument))), expected.value,
                    `leaf ${at}`);
            }
        });

        test(`${label}: every nonce hash`, () => {
            for (const [at, leaf] of vector.leaves.entries()) {
                assert.strictEqual(hex(lndecode.nonceHash(tlvs[at], firstTlv)), nonceOf(leaf).value,
                    `nonce ${at}`);
            }
        });

        test(`${label}: every leaf node`, () => {
            for (const [at, leaf] of vector.leaves.entries()) {
                assert.strictEqual(hex(lndecode.leafNode(tlvs[at], firstTlv)), nodeOf(leaf).value,
                    `node ${at}`);
            }
        });

        test(`${label}: every published branch is reproducible from its two inputs`, () => {
            for (const branch of vector.branches) {
                const { argument, value } = branchOf(branch);
                const left = bytes(argument.slice(0, 64));
                const right = bytes(argument.slice(64));
                assert.strictEqual(hex(lndecode.branchNode(left, right)), value, branch.desc);
            }
        });

        test(`${label}: the tree computes exactly the published branches`, () => {
            const computed = computedBranches(lndecode.merkleLevels(tlvs)).sort();
            const published = vector.branches.map(b => branchOf(b).value).sort();
            assert.deepStrictEqual(computed, published);
        });

        test(`${label}: the root`, () => {
            assert.strictEqual(hex(lndecode.merkleRoot(tlvs)), vector.merkle);
        });
    }
});

describe('signature hash', () => {
    const VECTOR = VECTORS.find(v => v.signature_tag !== undefined);

    test('exactly one vector carries a signature tag', () => {
        assert.strictEqual(VECTORS.filter(v => v.signature_tag !== undefined).length, 1);
    });

    test('the tag is "lightning" then the message name then the field name', () => {
        assert.strictEqual(VECTOR.signature_tag, 'lightning' + VECTOR.tlv + 'signature');
    });

    test('H(signature_tag, merkle) matches', () => {
        assert.strictEqual(
            hex(lndecode.signatureHash(VECTOR.tlv, 'signature', bytes(VECTOR.merkle))),
            VECTOR['H(signature_tag,merkle)']);
    });

    test('a different field name gives a different hash', () => {
        assert.notStrictEqual(
            hex(lndecode.signatureHash(VECTOR.tlv, 'proof_signature', bytes(VECTOR.merkle))),
            VECTOR['H(signature_tag,merkle)']);
    });
});

describe('merkle roots from decoded streams', () => {
    test('parseTlvStream retains each record\'s raw bytes', () => {
        const stream = bytes('010203e802080000010000020003');
        const records = lndecode.parseTlvStream(stream);
        assert.deepStrictEqual(Array.from(records, r => hex(r.tlv)),
            ['010203e8', '02080000010000020003']);
    });

    test('the invoice_request vector\'s root is reachable from its bech32 string', () => {
        const VECTOR = VECTORS.find(v => v.bolt12 !== undefined);
        const split = lndecode.bolt12ToBytes(VECTOR.bolt12);
        assert.strictEqual(split.prefix, 'lnr');
        const records = lndecode.parseTlvStream(split.bytes);
        // The signature is the field being signed, so it is not part of the tree.
        const signed = Array.from(records).filter(r => r.type !== 240n);
        assert.strictEqual(signed.length, VECTOR.leaves.length);
        assert.strictEqual(hex(lndecode.merkleRoot(signed.map(r => r.tlv))), VECTOR.merkle);
    });

    test('an empty record list is an error', () => {
        assert.throws(() => lndecode.merkleRoot([]), /at least one tlv record/i);
    });
});
