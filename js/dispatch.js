// Routes a request string to a decoder and flattens the result into a display model.

const BOLT11_PREFIXES = new Map([
    ['lnbc', 'bitcoin mainnet'],
    ['lntb', 'bitcoin testnet'],
    ['lnbcrt', 'bitcoin regtest'],
    ['lnsb', 'bitcoin simnet'],
    ['lntbs', 'bitcoin signet']
]);

const BOLT12_PREFIXES = new Map([
    ['lno', 'offer'],
    ['lnr', 'invoice request'],
    ['lnp', 'payer proof']
]);

const BOLT11_TAG_LABELS = new Map([
    ['p', 'Payment Hash'],
    ['s', 'Payment Secret'],
    ['d', 'Description'],
    ['n', 'Destination'],
    ['h', 'Description Hash'],
    ['x', 'Expiration Time'],
    ['c', 'Min Final CLTV Expiry Delta'],
    ['f', 'Fallback On-Chain Address'],
    ['r', 'Routing Info'],
    ['9', 'Feature Bits'],
    ['m', 'Payment Metadata']
]);

const FIELD_LABELS = new Map([
    ['version', 'Version'],
    ['fallback_address', 'Fall Back Address'],
    ['public_key', 'Public Key'],
    ['short_channel_id', 'Short Channel Id'],
    ['fee_base_msat', 'Fee Base Msat'],
    ['fee_proportional_millionths', 'Fee Proportional Millionths'],
    ['cltv_expiry_delta', 'CLTV Expiry Delta'],
    ['r', 'R value'],
    ['s', 'S value'],
    ['recovery_flag', 'Recovery Flag'],
    ['payee_public_key', 'Payee Public Key']
]);

function decodeRequest(request) {
    if (typeof request !== 'string') {
        throw new Error('Invalid input: payment request must be a string');
    }

    // The prefix is read from a copy with '+' and whitespace removed. Decoding uses the
    // original string.
    let probe = request.replace(/\+\s*/g, '').replace(/\s+/g, '');
    requireConsistentCase(probe);
    let prefix = readPrefix(probe.toLowerCase());

    if (BOLT11_PREFIXES.has(prefix)) {
        return bolt11Model(decode(request), prefix);
    }
    if (prefix === 'lno') {
        return offerModel(decodeOffer(request));
    }
    if (BOLT12_PREFIXES.has(prefix)) {
        throw new Error('Not yet supported: bolt12 ' + BOLT12_PREFIXES.get(prefix) + ' decoding');
    }
    throw new Error('Malformed request: unknown prefix');
}

// Renders BigInt as a string, and omits the character breakdown, which the Raw Data
// section already shows.
function jsonReplacer(key, value) {
    if (key === 'raw_parts') return undefined;
    return typeof value === 'bigint' ? value.toString() : value;
}

function subRows(object) {
    return Object.keys(object).map(key => ({
        label: FIELD_LABELS.get(key),
        value: object[key]
    }));
}

function bolt11Model(decoded, prefix) {
    let rows = [];

    rows.push({ label: 'Network', value: BOLT11_PREFIXES.get(prefix) });

    let btc = decoded.human_readable_part.amount / 100000000000;
    rows.push({
        label: 'Amount',
        value: Number.isNaN(btc) ? 'any payment amount' : toFixed(btc) + ' BTC'
    });

    rows.push({ label: 'Date', value: epochToDate(decoded.data.time_stamp) });

    let tags = decoded.data.tags;
    for (const tag of tags) {
        switch (tag.type) {
            case 'f':
                rows.push({ label: BOLT11_TAG_LABELS.get('f'), sub: subRows(tag.value) });
                break;
            case 'r':
                tag.value.forEach((hop, index) => rows.push({
                    label: BOLT11_TAG_LABELS.get('r') + (tag.value.length > 1 ? ' ' + (index + 1) : ''),
                    sub: subRows(hop)
                }));
                break;
            case 'x':
                rows.push({ label: BOLT11_TAG_LABELS.get(tag.type), value: tag.value + ' seconds' });
                break;
            case 'p':
            case 's':
            case 'd':
            case 'n':
            case 'h':
            case 'c':
            case '9':
            case 'm':
                rows.push({ label: BOLT11_TAG_LABELS.get(tag.type), value: tag.value });
                break;
        }
    }

    if (!tags.some(tag => tag.type === 'x')) {
        rows.push({ label: BOLT11_TAG_LABELS.get('x'), value: 3600 + ' seconds' });
    }
    if (!tags.some(tag => tag.type === 'c')) {
        rows.push({ label: BOLT11_TAG_LABELS.get('c'), value: 18 });
    }

    rows.push({ label: 'Signature', sub: subRows(decoded.data.signature) });
    rows.push({ label: 'Signing Data', value: decoded.data.signing_data });
    rows.push({ label: 'Checksum', value: decoded.checksum });

    return {
        kind: 'bolt11-invoice',
        prefix: prefix,
        sections: [
            { title: 'Payment Info:', rows: rows },
            { title: 'Raw Data:', rows: breakdownRows(decoded.raw_parts) }
        ],
        jsonTitle: 'Decoded JSON:',
        raw: decoded
    };
}

// One row per character group of the request. A tagged field is split into the three
// groups it is written from.
function breakdownRows(parts) {
    return parts.map(part => {
        if (part.type === undefined) {
            return { label: part.name, value: part.chars };
        }
        return {
            label: part.name + ' (' + (BOLT11_TAG_LABELS.get(part.type) || 'unknown') + ')',
            sub: [
                { label: 'type', value: part.type },
                { label: 'data_length', value: part.length_chars + ' (' + part.data_length + ')' },
                { label: 'data', value: part.chars }
            ]
        };
    });
}

// --- bolt12 offers -----------------------------------------------------------

// Genesis hashes named by the bolt12 test vectors. Anything else renders as hex.
const CHAIN_NAMES = new Map([
    ['6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000', 'bitcoin mainnet'],
    ['43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000', 'bitcoin testnet'],
    ['1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003', 'liquidv1']
]);

function offerField(offer, name) {
    let field = offer.fields.find(entry => entry.name === name);
    return field === undefined ? undefined : field.value;
}

// Returns the bit numbers set in a feature bitmap, most significant first.
function setFeatureBits(hex) {
    let bytes = hexStringToByteArray(hex);
    let bits = [];
    for (let bit = bytes.length * 8 - 1; bit >= 0; bit--) {
        if ((bytes[bytes.length - 1 - (bit >> 3)] >> (bit % 8)) & 1) bits.push(bit);
    }
    return bits;
}

function firstNodeIdText(firstNodeId) {
    if (firstNodeId.node_id !== undefined) return firstNodeId.node_id;
    return 'short channel id ' + firstNodeId.short_channel_id + ', direction ' + firstNodeId.direction;
}

function blindedPathRow(path, index) {
    let sub = [
        { label: 'First Node Id', value: firstNodeIdText(path.first_node_id) },
        { label: 'Path Key', value: path.first_path_key }
    ];
    path.path.forEach((hop, hopIndex) => {
        sub.push({ label: 'Hop ' + (hopIndex + 1) + ' Blinded Id', value: hop.blinded_node_id });
    });
    return { label: 'Blinded Path ' + (index + 1), sub: sub };
}

function offerModel(offer) {
    let rows = [];

    let chains = offerField(offer, 'offer_chains');
    rows.push({
        label: 'Chains',
        value: chains === undefined
            ? 'bitcoin mainnet'
            : chains.map(hash => CHAIN_NAMES.get(hash) || hash).join(', ')
    });

    // A currency amount is in that currency's ISO 4217 minor unit, so 10000 USD is
    // 100.00 dollars. The exponent is not carried in the offer.
    let amount = offerField(offer, 'offer_amount');
    let currency = offerField(offer, 'offer_currency');
    rows.push({
        label: 'Amount',
        value: amount === undefined
            ? 'any amount'
            : currency === undefined
                ? amount.toString() + ' msat'
                : amount.toString() + ' ' + currency + ' (minor units)'
    });

    let description = offerField(offer, 'offer_description');
    if (description !== undefined) {
        rows.push({ label: 'Description', value: description });
    }

    let issuer = offerField(offer, 'offer_issuer');
    if (issuer !== undefined) {
        rows.push({ label: 'Issuer', value: issuer });
    }

    let expiry = offerField(offer, 'offer_absolute_expiry');
    if (expiry !== undefined) {
        rows.push({ label: 'Expires', value: epochToDate(Number(expiry)) });
    }

    let quantityMax = offerField(offer, 'offer_quantity_max');
    if (quantityMax !== undefined) {
        rows.push({
            label: 'Quantity Max',
            value: quantityMax === 0n ? 'unlimited' : quantityMax.toString()
        });
    }

    let features = offerField(offer, 'offer_features');
    if (features !== undefined) {
        let bits = setFeatureBits(features);
        rows.push({ label: 'Feature Bits', value: bits.length === 0 ? 'none' : bits.join(', ') });
    }

    let metadata = offerField(offer, 'offer_metadata');
    if (metadata !== undefined) {
        rows.push({ label: 'Metadata', value: metadata });
    }

    let paths = offerField(offer, 'offer_paths');
    if (paths !== undefined) {
        paths.forEach((path, index) => rows.push(blindedPathRow(path, index)));
    }

    let issuerId = offerField(offer, 'offer_issuer_id');
    if (issuerId !== undefined) {
        rows.push({ label: 'Issuer Id', value: issuerId });
    }

    return {
        kind: 'bolt12-offer',
        prefix: offer.prefix,
        sections: [
            { title: 'Offer Info:', rows: rows },
            { title: 'Raw Data:', rows: offerBreakdownRows(offer) }
        ],
        jsonTitle: 'Decoded JSON:',
        raw: offer
    };
}

// An offer's payload is a byte stream, so its groups are the tlv records rather than
// character runs.
function offerBreakdownRows(offer) {
    let rows = [
        { label: 'prefix', value: offer.prefix },
        { label: 'separator', value: '1' }
    ];
    for (const record of offer.raw_records) {
        rows.push({
            label: 'tlv ' + record.type + ' (' + (record.name || 'unknown') + ')',
            sub: [
                { label: 'type', value: String(record.type) },
                { label: 'length', value: String(record.length) },
                { label: 'value', value: record.hex }
            ]
        });
    }
    return rows;
}
