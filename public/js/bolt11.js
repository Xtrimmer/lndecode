// BOLT 11 invoice decoding: a six-character bech32 checksum over 5-bit tagged fields.
//
// The description behind an 'h' field travels out of band, so verifying it is a separate
// call: see descriptionMatchesHash.

const TIMESTAMP_LENGTH = 7;
const SIGNATURE_LENGTH = 104;
const ROUTE_HOP_LENGTH = 51;

function decode(paymentRequest) {
    if (typeof paymentRequest !== 'string') {
        throw new Error('Invalid input: payment request must be a string');
    }

    const stripped = paymentRequest.replace(/\s+/g, '');
    requireConsistentCase(stripped);

    const input = stripped.toLowerCase();
    const splitPosition = input.lastIndexOf('1');
    if (splitPosition < 1) {
        throw new Error('Malformed request: missing separator');
    }
    const humanReadablePart = input.substring(0, splitPosition);
    const data = input.substring(splitPosition + 1, input.length - 6);
    const checksum = input.substring(input.length - 6, input.length);
    if (data.length < TIMESTAMP_LENGTH + SIGNATURE_LENGTH) {
        throw new Error(`Malformed request: data part is too short at ${data.length} characters, needs at least ${TIMESTAMP_LENGTH + SIGNATURE_LENGTH}`);
    }
    if (!verify_checksum(humanReadablePart, bech32ToFiveBitArray(data + checksum))) {
        throw new Error('Malformed request: checksum is incorrect'); // A reader MUST fail if the checksum is incorrect.
    }
    const decodedData = decodeData(data, humanReadablePart);
    verifySignature(decodedData);
    const humanReadable = decodeHumanReadablePart(humanReadablePart);
    return {
        'human_readable_part': humanReadable,
        'data': decodedData,
        checksum,
        'raw_parts': rawParts(humanReadablePart, humanReadable.prefix, data, checksum)
    }
}

// The request split into the character groups it is written from. Concatenating every
// part reproduces the request.
function rawParts(humanReadablePart, prefix, data, checksum) {
    const parts = [{ 'name': 'prefix', 'chars': prefix }];

    const amountChars = humanReadablePart.substring(prefix.length);
    if (amountChars.length > 0) {
        parts.push({ 'name': 'amount', 'chars': amountChars });
    }
    parts.push({ 'name': 'separator', 'chars': '1' });
    parts.push({ 'name': 'timestamp', 'chars': data.substring(0, TIMESTAMP_LENGTH) });

    const tagData = data.substring(TIMESTAMP_LENGTH, data.length - SIGNATURE_LENGTH);
    for (const tag of extractTags(tagData)) {
        parts.push({
            'name': `tagged field ${tag.type}`,
            'type': tag.type,
            'length_chars': tag.length_chars,
            'data_length': tag.length,
            'chars': tag.data
        });
    }

    parts.push({ 'name': 'signature', 'chars': data.substring(data.length - SIGNATURE_LENGTH) });
    parts.push({ 'name': 'checksum', 'chars': checksum });
    return parts;
}

// Joins the parts back into the request they came from.
function rawPartsToString(parts) {
    let joined = '';
    for (const part of parts) {
        if (part.type !== undefined) joined += part.type + part.length_chars;
        joined += part.chars;
    }
    return joined;
}

// Compares an invoice's description_hash against a description supplied by the caller.
// A reader must check the two match; the description is not carried in the invoice.
function descriptionMatchesHash(paymentRequest, description) {
    const hashField = decode(paymentRequest).data.tags.find(tag => tag.type === 'h');
    if (hashField === undefined) {
        throw new Error('Invalid input: this request has no description hash');
    }
    return hashField.value === byteArrayToHexString(sha256(textToByteArray(description)));
}

// With an 'n' field the signature must verify against that key and must be low-S.
// Without one, the key is recovered, and both high-S and low-S are accepted.
function verifySignature(data) {
    const hash = new Uint8Array(sha256(hexStringToByteArray(data.signing_data)));
    const compact = new Uint8Array(hexStringToByteArray(data.signature.r + data.signature.s));
    const payeeKey = data.tags.find(tag => tag.type === 'n');

    if (payeeKey !== undefined) {
        const key = new Uint8Array(hexStringToByteArray(payeeKey.value));
        if (!secp256k1.verify(compact, hash, key, { prehash: false })) {
            throw new Error('Malformed request: signature does not verify against the payee public key');
        }
        data.signature.payee_public_key = payeeKey.value;
        return;
    }

    const recoverable = new Uint8Array(
        [data.signature.recovery_flag].concat(hexStringToByteArray(data.signature.r + data.signature.s)));
    let recovered;
    try {
        recovered = secp256k1.recoverPublicKey(recoverable, hash, { prehash: false });
    } catch (cause) {
        throw new Error('Malformed request: signature is not recoverable', { cause });
    }
    data.signature.payee_public_key = byteArrayToHexString(recovered);
}

function decodeHumanReadablePart(humanReadablePart) {
    const prefixes = ['lnbc', 'lntb', 'lnbcrt', 'lnsb', 'lntbs'];
    let prefix;
    prefixes.forEach(value => {
        if (humanReadablePart.substring(0, value.length) === value) {
            prefix = value;
        }
    });
    // A reader MUST fail if it does not understand the prefix.
    if (prefix === undefined) throw new Error('Malformed request: unknown prefix');
    const amount = decodeAmount(humanReadablePart.substring(prefix.length, humanReadablePart.length));
    return {
        prefix,
        amount
    }
}

function decodeData(data, humanReadablePart) {
    const date32 = data.substring(0, 7);
    const dateEpoch = bech32ToInt(date32);
    const signature = data.substring(data.length - 104, data.length);
    const tagData = data.substring(7, data.length - 104);
    const decodedTags = decodeTags(tagData, readPrefix(humanReadablePart));
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
    const bytes = fiveBitArrayTo8BitArray(bech32ToFiveBitArray(data));
    const hops = [];
    for (let offset = 0; offset + ROUTE_HOP_LENGTH <= bytes.length; offset += ROUTE_HOP_LENGTH) {
        const hop = bytes.slice(offset, offset + ROUTE_HOP_LENGTH);
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
    const data = fiveBitArrayTo8BitArray(bech32ToFiveBitArray(signature));
    const recoveryFlag = data[data.length - 1];
    const r = byteArrayToHexString(data.slice(0, 32));
    const s = byteArrayToHexString(data.slice(32, data.length - 1));
    return {
        r,
        s,
        'recovery_flag': recoveryFlag
    }
}

function decodeAmount(str) {
    // A reader SHOULD indicate if amount is unspecified.
    if (str.length === 0) {
        return 'Any amount';
    }
    const multiplier = isDigit(str.charAt(str.length - 1)) ? '-' : str.charAt(str.length - 1);
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
    const features = decodedTags.find(tag => tag.type === '9');
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
            throw new Error(`Malformed request: unknown even feature bit ${bit}`);
        }
    }
}

function decodeTags(tagData, prefix) {
    const tags = extractTags(tagData);
    const decodedTags = [];
    tags.forEach(value => decodedTags.push(decodeTag(value.type, value.length, value.data, prefix)));
    return decodedTags.filter(t => t !== undefined);
}

function extractTags(str) {
    const tags = [];
    while (str.length > 0) {
        const type = str.charAt(0);
        const lengthChars = str.substring(1, 3);
        const dataLength = bech32ToInt(lengthChars);
        const data = str.substring(3, dataLength + 3);
        tags.push({
            type,
            'length_chars': lengthChars,
            'length': dataLength,
            data
        });
        str = str.substring(3 + dataLength, str.length);
    }
    return tags;
}

function decodeTag(type, length, data, prefix) {
    switch (type) {
        case 'p':
            if (length !== 52) break; // A reader MUST skip over a 'p' field that does not have data_length 52
            return {
                type,
                length,
                'description': 'payment_hash',
                'value': byteArrayToHexString(fiveBitArrayTo8BitArray(bech32ToFiveBitArray(data)))
            };
        case 's':
            if (length !== 52) break; // A reader MUST skip over a 's' field that does not have data_length 52
            return {
                type,
                length,
                'description': 'payment_secret',
                'value': byteArrayToHexString(fiveBitArrayTo8BitArray(bech32ToFiveBitArray(data)))
            };
        case 'd':
            return {
                type,
                length,
                'description': 'description',
                'value': bech32ToUTF8String(data)
            };
        case 'n':
            if (length !== 53) break; // A reader MUST skip over a 'n' field that does not have data_length 53
            return {
                type,
                length,
                'description': 'payee_public_key',
                'value': byteArrayToHexString(fiveBitArrayTo8BitArray(bech32ToFiveBitArray(data)))
            };
        case 'h':
            if (length !== 52) break; // A reader MUST skip over a 'h' field that does not have data_length 52
            return {
                type,
                length,
                'description': 'description_hash',
                'value': byteArrayToHexString(fiveBitArrayTo8BitArray(bech32ToFiveBitArray(data)))
            };
        case 'x':
            return {
                type,
                length,
                'description': 'expiry',
                'value': bech32ToInt(data)
            };
        case 'c':
            return {
                type,
                length,
                'description': 'min_final_cltv_expiry_delta',
                'value': bech32ToInt(data)
            };
        case 'f': {
            const version = bech32ToFiveBitArray(data.charAt(0))[0];
            // A reader MUST skip over an f field with unknown version.
            if (version < 0 || version > 18) break;
            return {
                type,
                length,
                'description': 'fallback_address',
                'value': {
                    version,
                    'fallback_address': fallbackAddress(version,
                        bech32ToFiveBitArray(data.substring(1, data.length)), prefix)
                }
            };
        }
        case 'r':
            return {
                type,
                length,
                'description': 'routing_information',
                'value': decodeRoutingInformation(data)
            };
        case 'm':
            return {
                type,
                length,
                'description': 'payment_metadata',
                'value': byteArrayToHexString(fiveBitArrayTo8BitArray(bech32ToFiveBitArray(data)))
            };
        case '9':
            return {
                type,
                length,
                'description': 'feature_bits',
                'value': bech32ToBinaryString(bech32ToFiveBitArray(data))
            };
        default:
        // reader MUST skip over unknown fields
    }
}


function verify_checksum(hrp, data) {
    hrp = expand(hrp);
    const all = hrp.concat(data);
    const bool = polymod(all);
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
    const byteArray = [];
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
    const int5Array = bech32ToFiveBitArray(str);
    const byteArray = fiveBitArrayTo8BitArray(int5Array);

    let utf8String = '';
    for (let i = 0; i < byteArray.length; i++) {
        utf8String += `%${(`0${byteArray[i].toString(16)}`).slice(-2)}`;
    }
    return decodeURIComponent(utf8String);
}

function bech32ToBinaryString(byteArray) {
    return Array.prototype.map.call(byteArray, (byte) => {
        return (`000000${byte.toString(2)}`).slice(-5);
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
