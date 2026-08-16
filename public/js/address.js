// Bitcoin address encoding for BOLT 11 fallback addresses.

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const BECH32_CONSTANT = 1;
const BECH32M_CONSTANT = 0x2bc830a3;

const FALLBACK_P2PKH_VERSION = 17;
const FALLBACK_P2SH_VERSION = 18;

// Per network: the bech32 prefix for segwit, and the base58 version bytes for P2PKH and
// P2SH.
const ADDRESS_ENCODINGS = new Map([
    ['lnbc', { hrp: 'bc', p2pkh: 0x00, p2sh: 0x05 }],
    ['lntb', { hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4 }],
    ['lntbs', { hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4 }],
    ['lnbcrt', { hrp: 'bcrt', p2pkh: 0x6f, p2sh: 0xc4 }],
    ['lnsb', { hrp: 'sb', p2pkh: 0x6f, p2sh: 0xc4 }]
]);

function base58Encode(bytes) {
    const digits = [0];
    for (const byte of bytes) {
        let carry = byte;
        for (let i = 0; i < digits.length; i++) {
            carry += digits[i] << 8;
            digits[i] = carry % 58;
            carry = (carry - digits[i]) / 58;
        }
        while (carry > 0) {
            digits.push(carry % 58);
            carry = (carry - (carry % 58)) / 58;
        }
    }

    let encoded = '';
    for (const byte of bytes) {
        if (byte !== 0) break;
        encoded += BASE58_ALPHABET.charAt(0);
    }
    for (let i = digits.length - 1; i >= 0; i--) {
        encoded += BASE58_ALPHABET.charAt(digits[i]);
    }
    return encoded;
}

// Appends the first four bytes of the double SHA-256 as a checksum.
function base58CheckEncode(bytes) {
    const checksum = sha256(sha256(bytes)).slice(0, 4);
    return base58Encode(bytes.concat(checksum));
}

function bech32Checksum(hrp, values, constant) {
    const residue = polymod(expand(hrp).concat(values).concat([0, 0, 0, 0, 0, 0])) ^ constant;
    const checksum = [];
    for (let i = 0; i < 6; i++) {
        checksum.push((residue >> (5 * (5 - i))) & 31);
    }
    return checksum;
}

function bech32Encode(hrp, values, constant) {
    const payload = values.concat(bech32Checksum(hrp, values, constant));
    let encoded = `${hrp}1`;
    for (const value of payload) {
        encoded += bech32CharValues.charAt(value);
    }
    return encoded;
}

// Renders a fallback address. Versions 17 and 18 are base58check; 0 to 16 are segwit,
// using bech32 for version 0 and bech32m above it.
function fallbackAddress(version, fiveBitProgram, prefix) {
    const encoding = ADDRESS_ENCODINGS.get(prefix);
    if (encoding === undefined) return undefined;

    if (version === FALLBACK_P2PKH_VERSION || version === FALLBACK_P2SH_VERSION) {
        const versionByte = version === FALLBACK_P2PKH_VERSION ? encoding.p2pkh : encoding.p2sh;
        return base58CheckEncode([versionByte].concat(fiveBitArrayTo8BitArray(fiveBitProgram)));
    }

    const constant = version === 0 ? BECH32_CONSTANT : BECH32M_CONSTANT;
    return bech32Encode(encoding.hrp, [version].concat(fiveBitProgram), constant);
}
