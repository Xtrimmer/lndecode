// The bech32 character layer.

const bech32CharValues = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

// Throws if the string contains both upper and lower case letters.
function requireConsistentCase(str) {
    if (/[a-z]/.test(str) && /[A-Z]/.test(str)) {
        throw new Error('Malformed request: mixed case is not allowed');
    }
}

function bech32ToFiveBitArray(str) {
    let array = [];
    for (let i = 0; i < str.length; i++) {
        array.push(bech32CharValues.indexOf(str.charAt(i)));
    }
    return array;
}

// Throws on the first character outside the bech32 alphabet.
function requireBech32Characters(str) {
    for (let i = 0; i < str.length; i++) {
        if (bech32CharValues.indexOf(str.charAt(i)) === -1) {
            throw new Error('Malformed request: invalid bech32 character "' + str.charAt(i) + '"');
        }
    }
}

// Repacks 5-bit groups into bytes and discards the trailing padding. The padding must be
// fewer than 5 bits and all zero.
function fiveBitArrayToBytes(int5Array) {
    let count = 0;
    let buffer = 0;
    let bytes = [];
    int5Array.forEach(value => {
        buffer = (buffer << 5) + value;
        count += 5;
        if (count >= 8) {
            bytes.push((buffer >> (count - 8)) & 255);
            count -= 8;
        }
    });
    if (count >= 5) {
        throw new Error('Malformed request: bech32 padding exceeds 4 bits');
    }
    if (count > 0 && (buffer & ((1 << count) - 1)) !== 0) {
        throw new Error('Malformed request: bech32 padding is non-zero');
    }
    return bytes;
}

// Returns the leading run of letters.
function readPrefix(str) {
    let match = str.match(/^[a-z]+/);
    if (match === null) throw new Error('Malformed request: no human-readable prefix');
    return match[0];
}
