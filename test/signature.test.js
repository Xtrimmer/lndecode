// SHA-256 and signature verification tests.

const { test, describe } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const { load } = require('./load.js');
const { VALID_VECTORS, INVALID_VECTORS } = require('./vectors.js');
const OFFER_VECTORS = require('./vectors/offers.json');

const lndecode = load();

const hex = bytes => lndecode.byteArrayToHexString(bytes);
const utf8 = text => Array.from(Buffer.from(text, 'utf8'));

describe('sha256', () => {
    const FIPS = [
        ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
        ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
        ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
            '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1']
    ];
    for (const [message, expected] of FIPS) {
        test(`FIPS 180-4: ${JSON.stringify(message.slice(0, 24))}`, () => {
            assert.strictEqual(hex(lndecode.sha256(utf8(message))), expected);
        });
    }

    test('one million a', () => {
        assert.strictEqual(hex(lndecode.sha256(new Array(1000000).fill(0x61))),
            'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
    });

    // Lengths either side of the 64-byte block and the 56-byte padding boundary.
    for (const length of [1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 1000]) {
        test(`matches the platform digest at ${length} bytes`, () => {
            const input = crypto.randomBytes(length);
            assert.strictEqual(hex(lndecode.sha256(Array.from(input))),
                crypto.createHash('sha256').update(input).digest('hex'));
        });
    }

    test('the digest is 32 bytes', () => {
        assert.strictEqual(lndecode.sha256([]).length, 32);
    });
});

describe('invoice signatures', () => {
    // The spec signs every example with the same key and names the payee in the first
    // example's description.
    const SPEC_PAYEE = '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad';

    test('recovery produces the payee key the spec documents', () => {
        const vector = VALID_VECTORS.find(v => v.description.includes('donation of any amount'));
        const decoded = lndecode.decode(vector.invoice);
        assert.strictEqual(decoded.data.signature.payee_public_key, SPEC_PAYEE);
    });

    test('every valid vector yields a payee key', () => {
        for (const v of VALID_VECTORS) {
            const key = lndecode.decode(v.invoice).data.signature.payee_public_key;
            assert.match(key, /^0[23][0-9a-f]{64}$/, v.description);
        }
    });

    test('an unrecoverable signature is rejected', () => {
        const vector = INVALID_VECTORS.find(v => /not recoverable/i.test(v.description));
        assert.throws(() => lndecode.decode(vector.invoice), /not recoverable/i);
    });

    test('a high-S signature is rejected when an n field is present', () => {
        const vector = INVALID_VECTORS.find(v => /high-S/i.test(v.description) && /n. field/i.test(v.description));
        assert.throws(() => lndecode.decode(vector.invoice), /does not verify/i);
    });

    test('a high-S signature is accepted when recovering', () => {
        const vector = VALID_VECTORS.find(v => /high-S/i.test(v.description));
        assert.doesNotThrow(() => lndecode.decode(vector.invoice));
    });

    test('a tampered signature is rejected', () => {
        const vector = VALID_VECTORS.find(v => v.description.includes('donation of any amount'));
        // Flip a character inside the signature, which sits before the 6-char checksum.
        const at = vector.invoice.length - 20;
        const swapped = vector.invoice.charAt(at) === 'q' ? 'p' : 'q';
        const tampered = vector.invoice.slice(0, at) + swapped + vector.invoice.slice(at + 1);
        assert.throws(() => lndecode.decode(tampered));
    });
});

describe('offer points', () => {
    test('an off-curve issuer id is rejected', () => {
        const vector = OFFER_VECTORS.find(v => v.description.includes('invalid offer_issuer_id'));
        assert.throws(() => lndecode.decodeOffer(vector.bolt12), /not a point on the secp256k1 curve/i);
    });

    test('the dummy path points in the valid vectors are on the curve', () => {
        // 0202...02 is a real curve point, which is why validating every point does not
        // reject the vectors that use it as a placeholder.
        for (const v of OFFER_VECTORS.filter(v => v.valid)) {
            assert.doesNotThrow(() => lndecode.decodeOffer(v.bolt12), v.description);
        }
    });
});

describe('vendored secp256k1', () => {
    test('exposes the pieces the decoders use', () => {
        for (const name of ['Point', 'Signature', 'verify', 'recoverPublicKey']) {
            assert.strictEqual(typeof lndecode.secp256k1[name], 'function', name);
        }
    });

    test('rejects a recovery id outside 0 to 3', () => {
        const sig = new Uint8Array(65).fill(1);
        sig[0] = 4;
        assert.throws(() => lndecode.secp256k1.recoverPublicKey(sig, new Uint8Array(32).fill(1),
            { prehash: false }));
    });
});
