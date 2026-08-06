// Fallback address encoding and description-hash tests.

const { test, describe } = require('node:test');
const assert = require('node:assert');

const { load } = require('./load.js');
const { VALID_VECTORS } = require('./vectors.js');

const lndecode = load();

function fallbackOf(substring) {
    const vector = VALID_VECTORS.find(v => v.description.includes(substring));
    assert.ok(vector, `no vector matching "${substring}"`);
    const field = lndecode.decode(vector.invoice).data.tags.find(tag => tag.type === 'f');
    assert.ok(field, `${substring} should carry an f field`);
    return field.value;
}

describe('fallback addresses', () => {
    // Each address below is the one the spec names in that vector's own description.
    const CASES = [
        ['fallback address mk2QpYatsKic', 17, 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP'],
        ['fallback address 1RustyRX2oai', 17, '1RustyRX2oai4EYYDpQGWvEL62BBGqN9T'],
        ['(P2SH) address', 18, '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX'],
        ['(P2WPKH) address', 0, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'],
        ['(P2WSH) address', 0, 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'],
        ['(P2TR) address', 1, 'bc1pptdvg0d2nj99568qn6ssdy4cygnwuxgw2ukmnwgwz7jpqjz2kszse2s3lm']
    ];
    for (const [substring, version, expected] of CASES) {
        test(`version ${version}: ${expected.slice(0, 20)}...`, () => {
            const fallback = fallbackOf(substring);
            assert.strictEqual(fallback.version, version);
            assert.strictEqual(fallback.fallback_address, expected);
        });
    }

    test('a testnet invoice yields a testnet address', () => {
        assert.match(fallbackOf('on testnet, with a fallback').fallback_address, /^[mn2]/);
    });

    test('version 0 uses bech32 and version 1 uses bech32m', () => {
        // The two differ only in the checksum constant, so a mixup would still produce a
        // plausible-looking string with a wrong tail.
        assert.strictEqual(fallbackOf('(P2WPKH) address').fallback_address.slice(-6), 'v8f3t4');
        assert.strictEqual(fallbackOf('(P2TR) address').fallback_address.slice(-6), 'e2s3lm');
    });

    test('base58 keeps a leading zero byte as a leading 1', () => {
        assert.match(fallbackOf('fallback address 1RustyRX2oai').fallback_address, /^1/);
    });
});

describe('description hash', () => {
    const HASHED = 'entire list of things';
    const DESCRIPTION = 'One piece of chocolate cake, one icecream cone, one pickle, one slice of '
        + 'swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, '
        + 'one cupcake, and one slice of watermelon';

    function invoice(substring) {
        const vector = VALID_VECTORS.find(v => v.description.includes(substring));
        assert.ok(vector, `no vector matching "${substring}"`);
        return vector.invoice;
    }

    test('the h field is reported as hex, like p, s and n', () => {
        const field = lndecode.decode(invoice(HASHED)).data.tags.find(tag => tag.type === 'h');
        assert.strictEqual(field.value,
            '3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1');
    });

    test('the description the spec documents matches the hash', () => {
        assert.strictEqual(lndecode.descriptionMatchesHash(invoice(HASHED), DESCRIPTION), true);
    });

    test('an altered description does not match', () => {
        assert.strictEqual(lndecode.descriptionMatchesHash(invoice(HASHED), `${DESCRIPTION}!`), false);
        assert.strictEqual(lndecode.descriptionMatchesHash(invoice(HASHED), ''), false);
    });

    test('an invoice with no description hash is an error', () => {
        assert.throws(() => lndecode.descriptionMatchesHash(invoice('cup of coffee'), 'anything'),
            /no description hash/i);
    });
});

describe('utf8 encoding', () => {
    test('encodes multibyte text as the spec does', () => {
        // The spec's signing data for the nonsense vector contains this sequence.
        assert.strictEqual(lndecode.byteArrayToHexString(lndecode.textToByteArray('ナンセンス 1杯')),
            'e3838ae383b3e382bbe383b3e382b92031e69daf');
    });

    test('round trips through the decoder', () => {
        for (const text of ['', 'abc', 'ナンセンス 1杯', 'emoji \u{1F600}']) {
            assert.strictEqual(lndecode.bytesToUtf8String(lndecode.textToByteArray(text)), text);
        }
    });
});
