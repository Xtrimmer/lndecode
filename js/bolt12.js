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

// --- Offer fields ------------------------------------------------------------

const POINT_LENGTH = 33;
const CHAIN_HASH_LENGTH = 32;

// Reads a compressed point: 33 bytes prefixed 0x02 or 0x03.
function readPoint(reader, what) {
    let bytes = reader.readBytes(POINT_LENGTH, what);
    if (bytes[0] !== 2 && bytes[0] !== 3) {
        throw new Error('Malformed request: ' + what + ' has prefix 0x'
            + ('0' + bytes[0].toString(16)).slice(-2) + ', expected 0x02 or 0x03');
    }
    return byteArrayToHexString(bytes);
}

// Reads a sciddir_or_pubkey: a direction byte and short channel id when the first byte
// is 0 or 1, otherwise a point.
function readSciddirOrPubkey(reader, what) {
    let kind = reader.peekByte(what);
    if (kind === 0 || kind === 1) {
        let bytes = reader.readBytes(1 + 8, what);
        return {
            direction: bytes[0],
            short_channel_id: byteArrayToHexString(bytes.slice(1))
        };
    }
    return { node_id: readPoint(reader, what) };
}

function readBlindedPath(reader) {
    let firstNodeId = readSciddirOrPubkey(reader, 'blinded_path first_node_id');
    let firstPathKey = readPoint(reader, 'blinded_path first_path_key');

    let numHops = reader.readByte('blinded_path num_hops');
    if (numHops === 0) {
        throw new Error('Malformed request: blinded_path has zero hops');
    }

    let hops = [];
    for (let i = 0; i < numHops; i++) {
        let blindedNodeId = readPoint(reader, 'blinded_path_hop blinded_node_id');
        let encryptedLength = Number(reader.readUint(2, 'blinded_path_hop enclen'));
        hops.push({
            blinded_node_id: blindedNodeId,
            encrypted_recipient_data: byteArrayToHexString(
                reader.readBytes(encryptedLength, 'blinded_path_hop encrypted_recipient_data'))
        });
    }
    return { first_node_id: firstNodeId, first_path_key: firstPathKey, path: hops };
}

// Splits the value into 32-byte chain hashes. At least one is required.
function decodeChains(bytes) {
    if (bytes.length === 0) {
        throw new Error('Malformed request: offer_chains has no entries');
    }
    if (bytes.length % CHAIN_HASH_LENGTH !== 0) {
        throw new Error('Malformed request: offer_chains length ' + bytes.length
            + ' is not a multiple of ' + CHAIN_HASH_LENGTH);
    }
    let chains = [];
    for (let i = 0; i < bytes.length; i += CHAIN_HASH_LENGTH) {
        chains.push(byteArrayToHexString(bytes.slice(i, i + CHAIN_HASH_LENGTH)));
    }
    return chains;
}

function decodeTruncatedUint(bytes, what) {
    let reader = byteReader(bytes);
    return reader.readTruncatedUint(bytes.length, what);
}

function decodePaths(bytes) {
    let reader = byteReader(bytes);
    let paths = [];
    while (reader.remaining() > 0) {
        paths.push(readBlindedPath(reader));
    }
    return paths;
}

function decodePointField(bytes, what) {
    let reader = byteReader(bytes);
    let point = readPoint(reader, what);
    reader.requireExhausted(what);
    return point;
}

const OFFER_FIELDS = new Map([
    [2n, { name: 'offer_chains', decode: decodeChains }],
    [4n, { name: 'offer_metadata', decode: byteArrayToHexString }],
    [6n, { name: 'offer_currency', decode: bytesToUtf8String }],
    [8n, { name: 'offer_amount', decode: b => decodeTruncatedUint(b, 'offer_amount') }],
    [10n, { name: 'offer_description', decode: bytesToUtf8String }],
    [12n, { name: 'offer_features', decode: byteArrayToHexString }],
    [14n, { name: 'offer_absolute_expiry', decode: b => decodeTruncatedUint(b, 'offer_absolute_expiry') }],
    [16n, { name: 'offer_paths', decode: decodePaths }],
    [18n, { name: 'offer_issuer', decode: bytesToUtf8String }],
    [20n, { name: 'offer_quantity_max', decode: b => decodeTruncatedUint(b, 'offer_quantity_max') }],
    [22n, { name: 'offer_issuer_id', decode: b => decodePointField(b, 'offer_issuer_id') }]
]);

// --- Offer validation --------------------------------------------------------

const OFFER_TYPE_RANGES = [[1n, 79n], [1000000000n, 1999999999n]];

// No feature bits are assigned for offers.
const KNOWN_OFFER_FEATURE_BITS = new Set();

function requireOfferTypeRanges(records) {
    for (const record of records) {
        let inRange = OFFER_TYPE_RANGES.some(range => record.type >= range[0] && record.type <= range[1]);
        if (!inRange) {
            throw new Error('Malformed request: tlv type ' + record.type
                + ' is outside the ranges an offer may use');
        }
    }
}

// Throws on an unknown even bit. An unknown odd bit is ignored.
function validateOfferFeatures(hex) {
    let bytes = hexStringToByteArray(hex);
    for (let bit = 0; bit < bytes.length * 8; bit++) {
        let isSet = (bytes[bytes.length - 1 - (bit >> 3)] >> (bit % 8)) & 1;
        if (!isSet) continue;
        if (bit % 2 === 0 && !KNOWN_OFFER_FEATURE_BITS.has(bit)) {
            throw new Error('Malformed request: unknown even offer feature bit ' + bit);
        }
    }
}

// Applies the offer rules that span more than one field.
function validateOffer(fields) {
    let present = name => fields.some(field => field.name === name);
    let valueOf = name => {
        let field = fields.find(entry => entry.name === name);
        return field === undefined ? undefined : field.value;
    };

    let features = valueOf('offer_features');
    if (features !== undefined) {
        validateOfferFeatures(features);
    }

    let amount = valueOf('offer_amount');
    if (amount !== undefined) {
        if (amount === 0n) {
            throw new Error('Malformed request: offer_amount must be greater than zero');
        }
        if (!present('offer_description')) {
            throw new Error('Malformed request: offer_amount requires offer_description');
        }
    }

    if (present('offer_currency') && amount === undefined) {
        throw new Error('Malformed request: offer_currency requires offer_amount');
    }

    if (!present('offer_issuer_id') && !present('offer_paths')) {
        throw new Error('Malformed request: an offer requires offer_issuer_id or offer_paths');
    }
}

function decodeOffer(request) {
    let parsed = parseOfferTlvStream(request);
    requireOfferTypeRanges(parsed.records);

    let fields = [];
    for (const record of parsed.records) {
        let field = OFFER_FIELDS.get(record.type);
        if (field === undefined) continue;
        fields.push({
            type: Number(record.type),
            name: field.name,
            length: record.length,
            value: field.decode(record.value)
        });
    }
    validateOffer(fields);
    return { prefix: parsed.prefix, fields: fields };
}
