// BOLT 11 invoice decoding: a six-character bech32 checksum over 5-bit tagged fields.
//
//TODO - A reader MUST check that the signature is valid (see the n tagged field)
//TODO - Tagged part of type f: the fallback on-chain address should be decoded into an address format
//TODO - A reader MUST check that the SHA-2 256 in the h field exactly matches the hashed description.
//TODO - A reader MUST use the n field to validate the signature instead of performing signature recovery if a valid n field is provided.

const TIMESTAMP_LENGTH = 7;
const SIGNATURE_LENGTH = 104;
const ROUTE_HOP_LENGTH = 51;

function decode(paymentRequest) {
    if (typeof paymentRequest !== 'string') {
        throw new Error('Invalid input: payment request must be a string');
    }

    let stripped = paymentRequest.replace(/\s+/g, '');
    requireConsistentCase(stripped);

    let input = stripped.toLowerCase();
    let splitPosition = input.lastIndexOf('1');
    if (splitPosition < 1) {
        throw new Error('Malformed request: missing separator');
    }
    let humanReadablePart = input.substring(0, splitPosition);
    let data = input.substring(splitPosition + 1, input.length - 6);
    let checksum = input.substring(input.length - 6, input.length);
    if (data.length < TIMESTAMP_LENGTH + SIGNATURE_LENGTH) {
        throw new Error('Malformed request: data part is too short at ' + data.length
            + ' characters, needs at least ' + (TIMESTAMP_LENGTH + SIGNATURE_LENGTH));
    }
    if (!verify_checksum(humanReadablePart, bech32ToFiveBitArray(data + checksum))) {
        throw new Error('Malformed request: checksum is incorrect'); // A reader MUST fail if the checksum is incorrect.
    }
    return {
        'human_readable_part': decodeHumanReadablePart(humanReadablePart),
        'data': decodeData(data, humanReadablePart),
        'checksum': checksum
    }
}

function decodeHumanReadablePart(humanReadablePart) {
    let prefixes = ['lnbc', 'lntb', 'lnbcrt', 'lnsb', 'lntbs'];
    let prefix;
    prefixes.forEach(value => {
        if (humanReadablePart.substring(0, value.length) === value) {
            prefix = value;
        }
    });
    if (prefix == null) throw new Error('Malformed request: unknown prefix'); // A reader MUST fail if it does not understand the prefix.
    let amount = decodeAmount(humanReadablePart.substring(prefix.length, humanReadablePart.length));
    return {
        'prefix': prefix,
        'amount': amount
    }
}

function decodeData(data, humanReadablePart) {
    let date32 = data.substring(0, 7);
    let dateEpoch = bech32ToInt(date32);
    let signature = data.substring(data.length - 104, data.length);
    let tagData = data.substring(7, data.length - 104);
    let decodedTags = decodeTags(tagData);
    validateTags(decodedTags);
    let value = bech32ToFiveBitArray(date32 + tagData);
    value = fiveBitArrayTo8BitArray(value, true);
    value = textToHexString(humanReadablePart).concat(byteArrayToHexString(value));
    return {
        'time_stamp': dateEpoch,
        'tags': decodedTags,
        'signature': decodeSignature(signature),
        'signing_data': value
    }
}

// An 'r' field carries one or more 51-byte hops.
function decodeRoutingInformation(data) {
    let bytes = fiveBitArrayTo8BitArray(bech32ToFiveBitArray(data));
    let hops = [];
    for (let offset = 0; offset + ROUTE_HOP_LENGTH <= bytes.length; offset += ROUTE_HOP_LENGTH) {
        let hop = bytes.slice(offset, offset + ROUTE_HOP_LENGTH);
        hops.push({
            'public_key': byteArrayToHexString(hop.slice(0, 33)),
            'short_channel_id': byteArrayToHexString(hop.slice(33, 41)),
            'fee_base_msat': byteArrayToInt(hop.slice(41, 45)),
            'fee_proportional_millionths': byteArrayToInt(hop.slice(45, 49)),
            'cltv_expiry_delta': byteArrayToInt(hop.slice(49, 51))
        });
    }
    return hops;
}

function decodeSignature(signature) {
    let data = fiveBitArrayTo8BitArray(bech32ToFiveBitArray(signature));
    let recoveryFlag = data[data.length - 1];
    let r = byteArrayToHexString(data.slice(0, 32));
    let s = byteArrayToHexString(data.slice(32, data.length - 1));
    return {
        'r': r,
        's': s,
        'recovery_flag': recoveryFlag
    }
}

function decodeAmount(str) {
    if (str.length == 0)
    {
        return 'Any amount' // A reader SHOULD indicate if amount is unspecified
    }
    let multiplier = isDigit(str.charAt(str.length - 1)) ? '-' : str.charAt(str.length - 1);
    let amount = multiplier === '-' ? str : str.substring(0, str.length - 1);
    if (amount.substring(0, 1) === '0') {
        throw new Error('Malformed request: amount cannot contain leading zeros');
    }
    // A reader MUST fail if the multiplier is 'p' and the last decimal of amount is
    // not 0: HTLCs are denominated in millisatoshis, so sub-millisatoshi amounts
    // cannot be transferred.
    if (multiplier === 'p' && amount.charAt(amount.length - 1) !== '0') {
        throw new Error('Malformed request: sub-millisatoshi precision is not allowed');
    }
    amount = Number(amount);
    if (amount < 0 || !Number.isInteger(amount)) {
        throw new Error('Malformed request: amount must be a positive decimal integer'); // A reader SHOULD fail if amount contains a non-digit
    }

    switch (multiplier) {
        case 'p':
            return amount / 10;
        case 'n':
            return amount * 100;
        case 'u':
            return amount * 100000;
        case 'm':
            return amount * 100000000;
        case '-':
            return amount * 100000000000;
        default:
            // A reader SHOULD fail if amount is followed by anything except a defined multiplier.
            throw new Error('Malformed request: undefined amount multiplier');
    }
}

// Feature bits assigned in BOLT 9, both members of each pair. ASSUMED features are
// included: older invoices still advertise them and a reader can safely ignore them.
const KNOWN_FEATURE_BITS = new Set([
    0, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 22, 23,
    24, 25, 26, 27, 28, 29, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
    46, 47, 48, 49, 50, 51, 60, 61, 62, 63, 66, 67
]);

function validateTags(decodedTags) {
    // A reader MUST fail if a valid 's' field is not provided.
    if (!decodedTags.some(tag => tag.type === 's')) {
        throw new Error('Malformed request: payment secret is required');
    }
    let features = decodedTags.find(tag => tag.type === '9');
    if (features !== undefined) {
        validateFeatureBits(features.value);
    }
}

// The field is big-endian: bit 0 is the least-significant bit of the last group.
function validateFeatureBits(binaryString) {
    for (let bit = 0; bit < binaryString.length; bit++) {
        if (binaryString.charAt(binaryString.length - 1 - bit) !== '1') continue;
        // A reader MUST ignore unknown odd bits, and MUST fail on unknown even bits.
        if (bit % 2 === 0 && !KNOWN_FEATURE_BITS.has(bit)) {
            throw new Error('Malformed request: unknown even feature bit ' + bit);
        }
    }
}

function decodeTags(tagData) {
    let tags = extractTags(tagData);
    let decodedTags = [];
    tags.forEach(value => decodedTags.push(decodeTag(value.type, value.length, value.data)));
    return decodedTags.filter(t => t !== undefined);
}

function extractTags(str) {
    let tags = [];
    while (str.length > 0) {
        let type = str.charAt(0);
        let dataLength = bech32ToInt(str.substring(1, 3));
        let data = str.substring(3, dataLength + 3);
        tags.push({
            'type': type,
            'length': dataLength,
            'data': data
        });
        str = str.substring(3 + dataLength, str.length);
    }
    return tags;
}

function decodeTag(type, length, data) {
    switch (type) {
        case 'p':
            if (length !== 52) break; // A reader MUST skip over a 'p' field that does not have data_length 52
            return {
                'type': type,
                'length': length,
                'description': 'payment_hash',
                'value': byteArrayToHexString(fiveBitArrayTo8BitArray(bech32ToFiveBitArray(data)))
            };
        case 's':
            if (length !== 52) break; // A reader MUST skip over a 's' field that does not have data_length 52
            return {
                'type': type,
                'length': length,
                'description': 'payment_secret',
                'value': byteArrayToHexString(fiveBitArrayTo8BitArray(bech32ToFiveBitArray(data)))
            };
        case 'd':
            return {
                'type': type,
                'length': length,
                'description': 'description',
                'value': bech32ToUTF8String(data)
            };
        case 'n':
            if (length !== 53) break; // A reader MUST skip over a 'n' field that does not have data_length 53
            return {
                'type': type,
                'length': length,
                'description': 'payee_public_key',
                'value': byteArrayToHexString(fiveBitArrayTo8BitArray(bech32ToFiveBitArray(data)))
            };
        case 'h':
            if (length !== 52) break; // A reader MUST skip over a 'h' field that does not have data_length 52
            return {
                'type': type,
                'length': length,
                'description': 'description_hash',
                'value': data
            };
        case 'x':
            return {
                'type': type,
                'length': length,
                'description': 'expiry',
                'value': bech32ToInt(data)
            };
        case 'c':
            return {
                'type': type,
                'length': length,
                'description': 'min_final_cltv_expiry_delta',
                'value': bech32ToInt(data)
            };
        case 'f':
            let version = bech32ToFiveBitArray(data.charAt(0))[0];
            if (version < 0 || version > 18) break; // a reader MUST skip over an f field with unknown version.
            data = data.substring(1, data.length);
            return {
                'type': type,
                'length': length,
                'description': 'fallback_address',
                'value': {
                    'version': version,
                    'fallback_address': data
                }
            };
        case 'r':
            return {
                'type': type,
                'length': length,
                'description': 'routing_information',
                'value': decodeRoutingInformation(data)
            };
        case 'm':
            return {
                'type': type,
                'length': length,
                'description': 'payment_metadata',
                'value': byteArrayToHexString(fiveBitArrayTo8BitArray(bech32ToFiveBitArray(data)))
            };
        case '9':
            return {
                'type': type,
                'length': length,
                'description': 'feature_bits',
                'value': bech32ToBinaryString(bech32ToFiveBitArray(data))
            };
        default:
        // reader MUST skip over unknown fields
    }
}

function polymod(values) {
    let GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    values.forEach((value) => {
        let b = (chk >> 25);
        chk = (chk & 0x1ffffff) << 5 ^ value;
        for (let i = 0; i < 5; i++) {
            if (((b >> i) & 1) === 1) {
                chk ^= GEN[i];
            } else {
                chk ^= 0;
            }
        }
    });
    return chk;
}

function expand(str) {
    let array = [];
    for (let i = 0; i < str.length; i++) {
        array.push(str.charCodeAt(i) >> 5);
    }
    array.push(0);
    for (let i = 0; i < str.length; i++) {
        array.push(str.charCodeAt(i) & 31);
    }
    return array;
}

function verify_checksum(hrp, data) {
    hrp = expand(hrp);
    let all = hrp.concat(data);
    let bool = polymod(all);
    return bool === 1;
}

// --- BOLT 11 field encodings -------------------------------------------------

function bech32ToInt(str) {
    let sum = 0;
    for (let i = 0; i < str.length; i++) {
        sum = sum * 32;
        sum = sum + bech32CharValues.indexOf(str.charAt(i));
    }
    return sum;
}

// Repacks 5-bit groups into bytes. Trailing bits are discarded, or padded into a final
// byte when includeOverflow is set.
function fiveBitArrayTo8BitArray(int5Array, includeOverflow) {
    let count = 0;
    let buffer = 0;
    let byteArray = [];
    int5Array.forEach((value) => {
        buffer = (buffer << 5) + value;
        count += 5;
        if (count >= 8) {
            byteArray.push(buffer >> (count - 8) & 255);
            count -= 8;
        }
    });
    if (includeOverflow && count > 0) {
        byteArray.push(buffer << (8 - count) & 255);
    }
    return byteArray;
}

function bech32ToUTF8String(str) {
    let int5Array = bech32ToFiveBitArray(str);
    let byteArray = fiveBitArrayTo8BitArray(int5Array);

    let utf8String = '';
    for (let i = 0; i < byteArray.length; i++) {
        utf8String += '%' + ('0' + byteArray[i].toString(16)).slice(-2);
    }
    return decodeURIComponent(utf8String);
}

function bech32ToBinaryString(byteArray) {
    return Array.prototype.map.call(byteArray, function (byte) {
        return ('000000' + byte.toString(2)).slice(-5);
    }).join('');
}

// Multiplies rather than shifting, which would truncate to 32 bits and turn a
// fee_base_msat above 2^31 negative.
function byteArrayToInt(byteArray) {
    let value = 0;
    for (let i = 0; i < byteArray.length; ++i) {
        value = value * 256 + byteArray[i];
    }
    return value;
}

function isDigit(str) { return str >= '0' && str <= '9' }
