// Routes a request string to a decoder and flattens the result into a display model.

const BOLT11_PREFIXES = new Map([
    ['lnbc', 'bitcoin mainnet'],
    ['lntb', 'bitcoin testnet'],
    ['lnbcrt', 'bitcoin regtest'],
    ['lnsb', 'bitcoin simnet'],
    ['lntbs', 'bitcoin signet']
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
    const probe = request.replace(/\+\s*/g, '').replace(/\s+/g, '');
    requireConsistentCase(probe);
    const prefix = readPrefix(probe.toLowerCase());

    if (BOLT11_PREFIXES.has(prefix)) {
        return bolt11Model(decode(request), prefix);
    }
    if (prefix === 'lno') {
        return offerModel(decodeOffer(request));
    }
    if (prefix === 'lnr') {
        return invoiceRequestModel(decodeInvoiceRequest(request));
    }
    if (prefix === 'lnp') {
        return payerProofModel(decodePayerProof(request));
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
    const rows = [];

    rows.push({ label: 'Network', value: BOLT11_PREFIXES.get(prefix) });

    const btc = decoded.human_readable_part.amount / 100000000000;
    rows.push({
        label: 'Amount',
        value: Number.isNaN(btc) ? 'any payment amount' : `${toFixed(btc)} BTC`
    });

    rows.push({ label: 'Date', value: epochToDate(decoded.data.time_stamp) });

    const tags = decoded.data.tags;
    for (const tag of tags) {
        switch (tag.type) {
            case 'f':
                rows.push({ label: BOLT11_TAG_LABELS.get('f'), sub: subRows(tag.value) });
                break;
            case 'r':
                tag.value.forEach((hop, index) => rows.push({
                    label: BOLT11_TAG_LABELS.get('r') + (tag.value.length > 1 ? ` ${index + 1}` : ''),
                    sub: subRows(hop)
                }));
                break;
            case 'x':
                rows.push({ label: BOLT11_TAG_LABELS.get(tag.type), value: `${tag.value} seconds` });
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
        rows.push({ label: BOLT11_TAG_LABELS.get('x'), value: `${3600} seconds` });
    }
    if (!tags.some(tag => tag.type === 'c')) {
        rows.push({ label: BOLT11_TAG_LABELS.get('c'), value: 18 });
    }

    rows.push({ label: 'Signature', sub: subRows(decoded.data.signature) });

    return {
        kind: 'bolt11-invoice',
        prefix,
        sections: [
            { title: 'Payment Info', emphasis: true, rows },
            { title: 'Invoice Breakdown', rows: breakdownRows(decoded.raw_parts) }
        ],
        jsonTitle: 'Decoded JSON',
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
            label: `${part.name} (${BOLT11_TAG_LABELS.get(part.type) || 'unknown'})`,
            sub: [
                { label: 'type', value: part.type },
                { label: 'data_length', value: `${part.length_chars} (${part.data_length})` },
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
    const field = offer.fields.find(entry => entry.name === name);
    return field === undefined ? undefined : field.value;
}

// Returns the bit numbers set in a feature bitmap, most significant first.
function setFeatureBits(hex) {
    const bytes = hexStringToByteArray(hex);
    const bits = [];
    for (let bit = bytes.length * 8 - 1; bit >= 0; bit--) {
        if ((bytes[bytes.length - 1 - (bit >> 3)] >> (bit % 8)) & 1) bits.push(bit);
    }
    return bits;
}

function firstNodeIdText(firstNodeId) {
    if (firstNodeId.node_id !== undefined) return firstNodeId.node_id;
    return `short channel id ${firstNodeId.short_channel_id}, direction ${firstNodeId.direction}`;
}

function blindedPathRow(path, index) {
    const sub = [
        { label: 'First Node Id', value: firstNodeIdText(path.first_node_id) },
        { label: 'Path Key', value: path.first_path_key }
    ];
    path.path.forEach((hop, hopIndex) => {
        sub.push({ label: `Hop ${hopIndex + 1} Blinded Id`, value: hop.blinded_node_id });
    });
    return { label: `Blinded Path ${index + 1}`, sub };
}

function offerModel(offer) {
    const rows = [];

    const chains = offerField(offer, 'offer_chains');
    rows.push({
        label: 'Chains',
        value: chains === undefined
            ? 'bitcoin mainnet'
            : chains.map(hash => CHAIN_NAMES.get(hash) || hash).join(', ')
    });

    // A currency amount is in that currency's ISO 4217 minor unit, so 10000 USD is
    // 100.00 dollars. The exponent is not carried in the offer.
    const amount = offerField(offer, 'offer_amount');
    const currency = offerField(offer, 'offer_currency');
    rows.push({
        label: 'Amount',
        value: amount === undefined
            ? 'any amount'
            : currency === undefined
                ? `${amount.toString()} msat`
                : `${amount.toString()} ${currency} (minor units)`
    });

    const description = offerField(offer, 'offer_description');
    if (description !== undefined) {
        rows.push({ label: 'Description', value: description });
    }

    const issuer = offerField(offer, 'offer_issuer');
    if (issuer !== undefined) {
        rows.push({ label: 'Issuer', value: issuer });
    }

    const expiry = offerField(offer, 'offer_absolute_expiry');
    if (expiry !== undefined) {
        rows.push({ label: 'Expires', value: epochToDate(Number(expiry)) });
    }

    const quantityMax = offerField(offer, 'offer_quantity_max');
    if (quantityMax !== undefined) {
        rows.push({
            label: 'Quantity Max',
            value: quantityMax === 0n ? 'unlimited' : quantityMax.toString()
        });
    }

    const features = offerField(offer, 'offer_features');
    if (features !== undefined) {
        const bits = setFeatureBits(features);
        rows.push({ label: 'Feature Bits', value: bits.length === 0 ? 'none' : bits.join(', ') });
    }

    const metadata = offerField(offer, 'offer_metadata');
    if (metadata !== undefined) {
        rows.push({ label: 'Metadata', value: metadata });
    }

    const paths = offerField(offer, 'offer_paths');
    if (paths !== undefined) {
        paths.forEach((path, index) => rows.push(blindedPathRow(path, index)));
    }

    const issuerId = offerField(offer, 'offer_issuer_id');
    if (issuerId !== undefined) {
        rows.push({ label: 'Issuer Id', value: issuerId });
    }

    return {
        kind: 'bolt12-offer',
        prefix: offer.prefix,
        sections: [
            { title: 'Offer Info', emphasis: true, rows },
            { title: 'Offer Breakdown', rows: offerBreakdownRows(offer) }
        ],
        jsonTitle: 'Decoded JSON',
        raw: offer
    };
}

// A bolt12 payload is a byte stream, so its groups are the tlv records rather than
// character runs.
function tlvBreakdownRows(prefix, records) {
    const rows = [
        { label: 'prefix', value: prefix },
        { label: 'separator', value: '1' }
    ];
    for (const record of records) {
        rows.push({
            label: `tlv ${record.type} (${record.name || 'unknown'})`,
            sub: [
                { label: 'type', value: String(record.type) },
                { label: 'length', value: String(record.length) },
                { label: 'value', value: record.hex }
            ]
        });
    }
    return rows;
}

function offerBreakdownRows(offer) {
    return tlvBreakdownRows(offer.prefix, offer.raw_records);
}

// --- bolt12 invoice requests -------------------------------------------------

function invreqField(invreq, name) {
    const field = invreq.fields.find(entry => entry.name === name);
    return field === undefined ? undefined : field.value;
}

// An amount alongside a currency is in that currency's ISO 4217 minor unit. Without one it
// is millisatoshi.
function amountText(amount, currency) {
    if (amount === undefined) return undefined;
    return currency === undefined
        ? `${amount.toString()} msat`
        : `${amount.toString()} ${currency} (minor units)`;
}

function invoiceRequestModel(invreq) {
    const rows = [];
    const field = name => invreqField(invreq, name);

    const chains = field('invreq_chain');
    rows.push({
        label: 'Chain',
        value: chains === undefined
            ? 'bitcoin mainnet'
            : chains.map(hash => CHAIN_NAMES.get(hash) || hash).join(', ')
    });

    const amount = amountText(field('invreq_amount'), undefined);
    const offerAmount = amountText(field('offer_amount'), field('offer_currency'));
    rows.push({ label: 'Amount Requested', value: amount === undefined ? 'unspecified' : amount });
    if (offerAmount !== undefined) {
        rows.push({ label: 'Offer Amount', value: offerAmount });
    }

    for (const [name, label] of [
        ['offer_description', 'Offer Description'],
        ['offer_issuer', 'Offer Issuer'],
        ['invreq_payer_note', 'Payer Note']
    ]) {
        const value = field(name);
        if (value !== undefined) rows.push({ label, value });
    }

    const expiry = field('offer_absolute_expiry');
    if (expiry !== undefined) {
        rows.push({ label: 'Offer Expires', value: epochToDate(Number(expiry)) });
    }

    const quantity = field('invreq_quantity');
    if (quantity !== undefined) {
        const max = field('offer_quantity_max');
        rows.push({
            label: 'Quantity',
            value: quantity.toString() + (max === undefined || max === 0n ? '' : ` of ${max}`)
        });
    }

    const bip353 = field('invreq_bip_353_name');
    if (bip353 !== undefined) {
        rows.push({ label: 'BIP 353 Name', value: `₿${bip353.name}@${bip353.domain}` });
    }

    for (const [name, label] of [
        ['invreq_features', 'Request Feature Bits'],
        ['offer_features', 'Offer Feature Bits']
    ]) {
        const features = field(name);
        if (features !== undefined) {
            const bits = setFeatureBits(features);
            rows.push({ label, value: bits.length === 0 ? 'none' : bits.join(', ') });
        }
    }

    for (const name of ['invreq_paths', 'offer_paths']) {
        const paths = field(name);
        if (paths !== undefined) {
            paths.forEach((path, index) => rows.push(blindedPathRow(path, index)));
        }
    }

    const metadata = field('offer_metadata');
    if (metadata !== undefined) {
        rows.push({ label: 'Offer Metadata', value: metadata });
    }

    const issuerId = field('offer_issuer_id');
    if (issuerId !== undefined) {
        rows.push({ label: 'Offer Issuer Id', value: issuerId });
    }

    rows.push({ label: 'Payer Id', value: field('invreq_payer_id') });
    rows.push({ label: 'Payer Metadata', value: field('invreq_metadata') });
    rows.push({ label: 'Signature', value: 'verified against Payer Id' });
    rows.push({ label: 'Merkle Root', value: invreq.merkle_root });

    return {
        kind: 'bolt12-invoice-request',
        prefix: invreq.prefix,
        sections: [
            { title: 'Invoice Request Info', emphasis: true, rows },
            { title: 'Invoice Request Breakdown', rows: tlvBreakdownRows(invreq.prefix, invreq.raw_records) }
        ],
        jsonTitle: 'Decoded JSON',
        raw: invreq
    };
}

// --- bolt12 payer proofs -----------------------------------------------------

// A proof's disclosed invoice fields are the ones in the tree it proves. Everything else
// in the stream is either a signature or proof scaffolding.
function disclosedRecords(proof) {
    const disclosed = new Set(proof.disclosed_types);
    return proof.raw_records.filter(record => disclosed.has(record.type));
}

function payerProofModel(proof) {
    const rows = [];

    rows.push({ label: 'Payment Preimage', value: proof.payment_preimage });
    rows.push({ label: 'Payment Hash', value: proof.payment_hash });
    if (proof.note !== undefined) {
        rows.push({ label: 'Note', value: proof.note });
    }

    const disclosed = disclosedRecords(proof);
    rows.push({
        label: 'Disclosed Fields',
        value: `${disclosed.length} of ${disclosed.length + proof.withheld_count}`,
        sub: disclosed.map(record => ({ label: record.name, value: record.hex }))
    });

    // Marker numbers hide which fields were held back, so only the count is knowable.
    rows.push({
        label: 'Withheld Fields',
        value: `${proof.withheld_count} withheld, identities hidden by the proof format`
    });

    rows.push({ label: 'Payer Id', value: proof.payer_id });
    rows.push({ label: 'Invoice Node Id', value: proof.node_id });
    rows.push({
        label: 'Invoice Signature',
        value: 'verified against Invoice Node Id',
        sub: [{ label: 'invoice merkle root', value: proof.invoice_merkle_root }]
    });
    rows.push({
        label: 'Proof Signature',
        value: 'verified against Payer Id',
        sub: [{ label: 'proof merkle root', value: proof.proof_merkle_root }]
    });

    return {
        kind: 'bolt12-payer-proof',
        prefix: proof.prefix,
        sections: [
            { title: 'Payer Proof Info', emphasis: true, rows },
            { title: 'Payer Proof Breakdown', rows: tlvBreakdownRows(proof.prefix, proof.raw_records) }
        ],
        jsonTitle: 'Decoded JSON',
        raw: proof
    };
}
