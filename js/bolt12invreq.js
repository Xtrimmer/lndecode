// BOLT 12 invoice request decoding.

const INVREQ_TYPE_RANGES = [[0n, 159n], [1000000000n, 2999999999n]];

// No feature bits are assigned for invoice requests.
const KNOWN_INVREQ_FEATURE_BITS = new Set();

const BIP_353_ALLOWED = /^[0-9A-Za-z\-_.]*$/;

const INVREQ_FIELDS = new Map([
    [0n, { name: 'invreq_metadata', decode: byteArrayToHexString }],
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
    [22n, { name: 'offer_issuer_id', decode: b => decodePointField(b, 'offer_issuer_id') }],
    [80n, { name: 'invreq_chain', decode: decodeChains }],
    [82n, { name: 'invreq_amount', decode: b => decodeTruncatedUint(b, 'invreq_amount') }],
    [84n, { name: 'invreq_features', decode: byteArrayToHexString }],
    [86n, { name: 'invreq_quantity', decode: b => decodeTruncatedUint(b, 'invreq_quantity') }],
    [88n, { name: 'invreq_payer_id', decode: b => decodePointField(b, 'invreq_payer_id') }],
    [89n, { name: 'invreq_payer_note', decode: bytesToUtf8String }],
    [90n, { name: 'invreq_paths', decode: decodePaths }],
    [91n, { name: 'invreq_bip_353_name', decode: decodeBip353Name }],
    [240n, { name: 'signature', decode: byteArrayToHexString }]
]);

// name and domain are each length-prefixed by one byte.
function decodeBip353Name(bytes) {
    let reader = byteReader(bytes);
    let name = bytesToUtf8String(reader.readBytes(reader.readByte('bip 353 name length'),
        'bip 353 name'));
    let domain = bytesToUtf8String(reader.readBytes(reader.readByte('bip 353 domain length'),
        'bip 353 domain'));
    reader.requireExhausted('invreq_bip_353_name');
    return { name: name, domain: domain };
}

function requireInvreqTypeRanges(records) {
    for (const record of records) {
        if (isSignatureType(record.type)) continue;
        let inRange = INVREQ_TYPE_RANGES.some(range =>
            record.type >= range[0] && record.type <= range[1]);
        if (!inRange) {
            throw new Error('Malformed request: tlv type ' + record.type
                + ' is outside the ranges an invoice request may use');
        }
    }
}

// Throws on an unknown even bit. An unknown odd bit is ignored.
function validateInvreqFeatures(hex) {
    let bytes = hexStringToByteArray(hex);
    for (let bit = 0; bit < bytes.length * 8; bit++) {
        let isSet = (bytes[bytes.length - 1 - (bit >> 3)] >> (bit % 8)) & 1;
        if (!isSet) continue;
        if (bit % 2 === 0 && !KNOWN_INVREQ_FEATURE_BITS.has(bit)) {
            throw new Error('Malformed request: unknown even invoice request feature bit ' + bit);
        }
    }
}

function requireBip353Characters(value) {
    for (const [part, text] of [['name', value.name], ['domain', value.domain]]) {
        if (!BIP_353_ALLOWED.test(text)) {
            throw new Error('Malformed request: invreq_bip_353_name ' + part
                + ' contains a disallowed character');
        }
    }
}

// Applies the invoice request rules that a decoder can check without knowing the offer it
// responds to, which chains the reader supports, or how it arrived.
function validateInvoiceRequest(fields) {
    let present = name => fields.some(field => field.name === name);
    let valueOf = name => {
        let field = fields.find(entry => entry.name === name);
        return field === undefined ? undefined : field.value;
    };

    if (!present('invreq_metadata')) {
        throw new Error('Malformed request: an invoice request requires invreq_metadata');
    }
    if (!present('invreq_payer_id')) {
        throw new Error('Malformed request: an invoice request requires invreq_payer_id');
    }

    let features = valueOf('invreq_features');
    if (features !== undefined) {
        validateInvreqFeatures(features);
    }

    let bip353 = valueOf('invreq_bip_353_name');
    if (bip353 !== undefined) {
        requireBip353Characters(bip353);
    }

    // The quantity and amount rules only apply to a request answering an offer, since
    // without one there are no offer fields to check against.
    let respondsToOffer = present('offer_issuer_id') || present('offer_paths');
    let quantityMax = valueOf('offer_quantity_max');
    let quantity = valueOf('invreq_quantity');
    let amount = valueOf('invreq_amount');

    if (!respondsToOffer) {
        for (const name of ['offer_chains', 'offer_features', 'offer_quantity_max']) {
            if (present(name)) {
                throw new Error('Malformed request: ' + name
                    + ' requires offer_issuer_id or offer_paths');
            }
        }
        if (amount === undefined) {
            throw new Error('Malformed request: invreq_amount is required without an offer');
        }
        return;
    }

    if (quantityMax === undefined) {
        if (quantity !== undefined) {
            throw new Error('Malformed request: invreq_quantity requires offer_quantity_max');
        }
    } else {
        if (quantity === undefined) {
            throw new Error('Malformed request: offer_quantity_max requires invreq_quantity');
        }
        if (quantityMax !== 0n && (quantity === 0n || quantity > quantityMax)) {
            throw new Error('Malformed request: invreq_quantity must be between 1 and '
                + quantityMax);
        }
    }

    let offerAmount = valueOf('offer_amount');
    if (offerAmount === undefined && amount === undefined) {
        throw new Error('Malformed request: invreq_amount is required when the offer has no amount');
    }
    // The expected amount is only computable when the offer amount is already in the
    // payable unit, which is to say when no currency conversion is involved.
    if (offerAmount !== undefined && amount !== undefined && !present('offer_currency')) {
        let expected = offerAmount * (quantity === undefined ? 1n : quantity);
        if (amount < expected) {
            throw new Error('Malformed request: invreq_amount ' + amount
                + ' is less than the expected ' + expected);
        }
    }
}

function decodeInvoiceRequest(request) {
    let split = bolt12ToBytes(request);
    if (split.prefix !== 'lnr') {
        throw new Error('Malformed request: expected an lnr invoice request, got ' + split.prefix);
    }

    let records = parseTlvStream(split.bytes);
    requireInvreqTypeRanges(records);
    requireUnderstoodTypes(records, new Set(INVREQ_FIELDS.keys()));

    // An unknown odd type reaches here and is carried through as raw bytes only.
    let fields = [];
    for (const record of records) {
        let known = INVREQ_FIELDS.get(record.type);
        if (known === undefined) continue;
        fields.push({
            type: Number(record.type),
            name: known.name,
            length: record.length,
            value: known.decode(record.value),
            hex: byteArrayToHexString(record.value)
        });
    }
    validateInvoiceRequest(fields);

    let byType = new Map(Array.from(records).map(record => [record.type, record]));
    if (!byType.has(240n)) {
        throw new Error('Malformed request: an invoice request requires a signature');
    }
    let payerId = byType.get(88n).value;
    if (!verifySignedStream('invoice_request', records, byType.get(240n).value, payerId)) {
        throw new Error('Malformed request: signature does not verify against invreq_payer_id');
    }

    let signed = signedRecords(records);
    return {
        prefix: split.prefix,
        fields: fields,
        merkle_root: byteArrayToHexString(merkleRoot(signed.map(record => record.tlv))),
        raw_records: Array.from(records).map(record => ({
            type: Number(record.type),
            name: INVREQ_FIELDS.has(record.type)
                ? INVREQ_FIELDS.get(record.type).name
                : undefined,
            length: record.length,
            hex: byteArrayToHexString(record.value)
        }))
    };
}
