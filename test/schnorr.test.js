// BIP-340 Schnorr verification and BOLT 12 signed-stream tests.

const { test, describe } = require('node:test');
const assert = require('node:assert');

const { load } = require('./load.js');
const BIP340 = require('./vectors/bip340.json');
const SIGNATURE_VECTORS = require('./vectors/signature.json');

const lndecode = load();

const hex = bytes => lndecode.byteArrayToHexString(bytes);
const bytes = string => lndecode.hexStringToByteArray(string);

function schnorrVerify(vector) {
    return lndecode.secp256k1.schnorr.verify(
        new Uint8Array(bytes(vector.signature)),
        new Uint8Array(bytes(vector.message)),
        new Uint8Array(bytes(vector.public_key)));
}

describe('the vendored sha256 hook', () => {
    // The library ships hashes.sha256 unset. Schnorr hashes internally, so without the
    // hook every verification returns false rather than throwing.
    test('is set', () => {
        assert.strictEqual(typeof lndecode.secp256k1.hashes.sha256, 'function');
    });

    test('returns a 32-byte Uint8Array', () => {
        const digest = lndecode.secp256k1.hashes.sha256(new Uint8Array([1, 2, 3]));
        // instanceof would compare against this realm's Uint8Array, not the sandbox's.
        assert.strictEqual(Object.prototype.toString.call(digest), '[object Uint8Array]');
        assert.strictEqual(digest.length, 32);
    });

    test('agrees with the module sha256', () => {
        const input = [0x61, 0x62, 0x63];
        assert.strictEqual(hex(Array.from(lndecode.secp256k1.hashes.sha256(new Uint8Array(input)))),
            hex(lndecode.sha256(input)));
    });
});

describe('BIP-340 published vectors', () => {
    test('there are 19, mixing valid and invalid', () => {
        assert.strictEqual(BIP340.length, 19);
        assert.strictEqual(BIP340.filter(v => v.valid).length, 9);
        assert.strictEqual(BIP340.filter(v => !v.valid).length, 10);
    });

    for (const vector of BIP340) {
        const label = vector.comment
            ? `[${vector.index}] rejects: ${vector.comment}`
            : `[${vector.index}] verifies`;
        test(label, () => {
            assert.strictEqual(schnorrVerify(vector), vector.valid);
        });
    }

    test('the suite covers messages other than 32 bytes', () => {
        // BOLT 12 always signs a 32-byte hash, but the suite exercises the general case.
        const lengths = new Set(BIP340.map(v => v.message.length / 2));
        assert.ok(lengths.size > 1, `only ${[...lengths]} byte lengths present`);
    });
});

describe('x-only points', () => {
    const X = '24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c';

    test('an even-Y compressed point drops its prefix', () => {
        assert.strictEqual(hex(lndecode.xOnlyPoint(bytes(`02${X}`))), X);
    });

    test('an odd-Y compressed point drops its prefix too', () => {
        assert.strictEqual(hex(lndecode.xOnlyPoint(bytes(`03${X}`))), X);
    });

    test('a bare x coordinate passes through', () => {
        assert.strictEqual(hex(lndecode.xOnlyPoint(bytes(X))), X);
    });

    for (const [label, input] of [
        ['an uncompressed point', `04${X}${X}`],
        ['a wrong prefix', `05${X}`],
        ['too short', `02${X.slice(0, 60)}`],
        ['empty', '']
    ]) {
        test(`${label} is an error`, () => {
            assert.throws(() => lndecode.xOnlyPoint(bytes(input)), /compressed point/i);
        });
    }
});

describe('bolt12 signature verification', () => {
    const VECTOR = SIGNATURE_VECTORS.find(v => v.bolt12 !== undefined);
    const records = Array.from(lndecode.parseTlvStream(lndecode.bolt12ToBytes(VECTOR.bolt12).bytes));
    const byType = new Map(records.map(r => [Number(r.type), r]));

    const PAYER_ID = byType.get(88).value;
    const ISSUER_ID = byType.get(22).value;
    const SIGNATURE = byType.get(240).value;

    test('the signature field is 64 bytes and matches the published signature', () => {
        assert.strictEqual(SIGNATURE.length, 64);
        assert.strictEqual(hex(SIGNATURE), VECTOR.signature);
    });

    test('an invoice_request is signed by invreq_payer_id', () => {
        assert.strictEqual(
            lndecode.verifySignedStream('invoice_request', records, SIGNATURE, PAYER_ID), true);
    });

    test('it does not verify against offer_issuer_id', () => {
        // Both keys are in the stream, so picking the wrong one has to fail loudly.
        assert.strictEqual(
            lndecode.verifySignedStream('invoice_request', records, SIGNATURE, ISSUER_ID), false);
    });

    test('the signature verifies against the published sighash directly', () => {
        assert.strictEqual(
            lndecode.verifyBolt12Signature(SIGNATURE, bytes(VECTOR['H(signature_tag,merkle)']),
                PAYER_ID), true);
    });

    test('a tampered signature fails', () => {
        const tampered = Array.from(SIGNATURE);
        tampered[0] ^= 0x01;
        assert.strictEqual(
            lndecode.verifySignedStream('invoice_request', records, tampered, PAYER_ID), false);
    });

    test('a tampered record fails', () => {
        // Flipping a bit in the description changes the merkle root and so the sighash.
        const mutated = records.map(r => r.type === 10n
            ? { type: r.type, length: r.length, value: r.value, tlv: flipLast(r.tlv) }
            : r);
        assert.strictEqual(
            lndecode.verifySignedStream('invoice_request', mutated, SIGNATURE, PAYER_ID), false);
    });

    test('the wrong message name fails', () => {
        assert.strictEqual(
            lndecode.verifySignedStream('invoice', records, SIGNATURE, PAYER_ID), false);
    });

    test('the signature record is excluded from the tree it signs', () => {
        const signed = lndecode.signedRecords(records);
        assert.strictEqual(signed.length, records.length - 1);
        assert.ok(!signed.some(r => r.type === 240n));
        assert.strictEqual(hex(lndecode.merkleRoot(signed.map(r => r.tlv))), VECTOR.merkle);
    });

    test('a signature of the wrong length is an error', () => {
        assert.throws(() => lndecode.verifyBolt12Signature(Array.from(SIGNATURE).slice(0, 63),
            bytes(VECTOR.merkle), PAYER_ID), /64 bytes/);
    });

    test('a stream holding only a signature is an error', () => {
        const only = records.filter(r => r.type === 240n);
        assert.throws(() => lndecode.verifySignedStream('invoice_request', only, SIGNATURE, PAYER_ID),
            /nothing to verify/i);
    });

    function flipLast(tlv) {
        const copy = Array.from(tlv);
        copy[copy.length - 1] ^= 0x01;
        return copy;
    }
});
