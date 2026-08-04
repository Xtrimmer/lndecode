// Byte-level helpers.

function byteArrayToHexString(byteArray) {
    return Array.prototype.map.call(byteArray, function (byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}

function hexStringToByteArray(hex) {
    if (hex.length % 2 !== 0) throw new Error('Invalid input: hex string has an odd length');
    let bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        let byte = parseInt(hex.substring(i, i + 2), 16);
        if (Number.isNaN(byte)) throw new Error('Invalid input: not a hex string');
        bytes.push(byte);
    }
    return bytes;
}

function textToHexString(text) {
    let hexString = '';
    for (let i = 0; i < text.length; i++) {
        hexString += text.charCodeAt(i).toString(16);
    }
    return hexString;
}

// A cursor over a byte array. Each read takes a name that appears in error messages.
function byteReader(bytes) {
    let offset = 0;

    function remaining() {
        return bytes.length - offset;
    }

    function requireAvailable(count, what) {
        if (remaining() < count) {
            throw new Error('Malformed request: truncated ' + what);
        }
    }

    function readByte(what) {
        requireAvailable(1, what);
        return bytes[offset++];
    }

    function readBytes(count, what) {
        requireAvailable(count, what);
        let out = bytes.slice(offset, offset + count);
        offset += count;
        return out;
    }

    // Reads a big-endian unsigned integer of a fixed width.
    function readUint(width, what) {
        let value = 0n;
        for (const byte of readBytes(width, what)) {
            value = (value << 8n) | BigInt(byte);
        }
        return value;
    }

    // Reads a BigSize: CompactSize, big-endian. Throws unless the encoding is the
    // shortest one for the value.
    function readBigSize(what) {
        let first = readByte(what);
        if (first < 0xfd) return BigInt(first);

        let width = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
        let minimum = first === 0xfd ? 0xfdn : first === 0xfe ? 0x10000n : 0x100000000n;
        let value = readUint(width, what);
        if (value < minimum) {
            throw new Error('Malformed request: ' + what + ' is not minimally encoded');
        }
        return value;
    }

    // Reads a tu64: big-endian over the bytes present, with no leading zero byte.
    function readTruncatedUint(width, what) {
        if (width > 0 && bytes[offset] === 0) {
            throw new Error('Malformed request: ' + what + ' has a leading zero byte');
        }
        return readUint(width, what);
    }

    function requireExhausted(what) {
        if (remaining() !== 0) {
            throw new Error('Malformed request: ' + remaining() + ' trailing bytes in ' + what);
        }
    }

    return {
        remaining: remaining,
        readByte: readByte,
        readBytes: readBytes,
        readUint: readUint,
        readBigSize: readBigSize,
        readTruncatedUint: readTruncatedUint,
        requireExhausted: requireExhausted
    };
}
