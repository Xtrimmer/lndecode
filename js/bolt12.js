// BOLT 12 decoding.

// Removes each '+' and any whitespace following it. A '+' must sit between two bech32
// characters.
function stripContinuations(str) {
    let result = '';
    let i = 0;
    while (i < str.length) {
        let ch = str.charAt(i);
        if (ch !== '+') {
            result += ch;
            i++;
            continue;
        }
        let next = i + 1;
        while (next < str.length && /\s/.test(str.charAt(next))) next++;
        let before = result.charAt(result.length - 1);
        let after = next < str.length ? str.charAt(next) : '';
        if (!isBech32Character(before) || !isBech32Character(after)) {
            throw new Error("Malformed request: '+' must be surrounded by bech32 characters");
        }
        i = next;
    }
    return result;
}

function normalizeBolt12(request) {
    if (typeof request !== 'string') {
        throw new Error('Invalid input: request must be a string');
    }
    requireConsistentCase(request);
    return stripContinuations(request.toLowerCase());
}

// Splits the prefix from the data part at the first '1'.
function splitBolt12(normalized) {
    let prefix = readPrefix(normalized);
    if (normalized.charAt(prefix.length) !== '1') {
        throw new Error('Malformed request: missing separator after prefix');
    }
    let data = normalized.substring(prefix.length + 1);
    if (data.length === 0) {
        throw new Error('Malformed request: no data after separator');
    }
    requireBech32Characters(data);
    return { prefix: prefix, data: data };
}

// Normalizes, splits, and unpacks the data part into bytes.
function bolt12ToBytes(request) {
    let split = splitBolt12(normalizeBolt12(request));
    return {
        prefix: split.prefix,
        bytes: fiveBitArrayToBytes(bech32ToFiveBitArray(split.data))
    };
}

// --- TLV stream --------------------------------------------------------------

// Reads a tlv_stream. Types and lengths are BigSize and minimally encoded, and types
// strictly increase.
function parseTlvStream(bytes) {
    let reader = byteReader(bytes);
    let records = [];
    let previousType = null;

    while (reader.remaining() > 0) {
        let type = reader.readBigSize('tlv type');
        let length = reader.readBigSize('tlv length');

        if (length > BigInt(reader.remaining())) {
            throw new Error('Malformed request: tlv length exceeds the bytes remaining');
        }
        if (previousType !== null && type <= previousType) {
            throw new Error('Malformed request: tlv types must strictly increase');
        }
        previousType = type;

        records.push({
            type: type,
            length: Number(length),
            value: reader.readBytes(Number(length), 'tlv value')
        });
    }
    return records;
}

// The types defined for an offer.
const OFFER_TLV_TYPES = new Set([2n, 4n, 6n, 8n, 10n, 12n, 14n, 16n, 18n, 20n, 22n]);

// Throws on an unknown even type. An unknown odd type is ignored.
function requireUnderstoodTypes(records, knownTypes) {
    for (const record of records) {
        if (knownTypes.has(record.type)) continue;
        if (record.type % 2n === 0n) {
            throw new Error('Malformed request: unknown even tlv type ' + record.type);
        }
    }
}

function parseOfferTlvStream(request) {
    let unpacked = bolt12ToBytes(request);
    let records = parseTlvStream(unpacked.bytes);
    requireUnderstoodTypes(records, OFFER_TLV_TYPES);
    return { prefix: unpacked.prefix, records: records };
}
