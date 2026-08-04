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
    ['c', 'Min Final CLTV Expiry'],
    ['f', 'Fallback On-Chain Address'],
    ['r', 'Routing Info'],
    ['9', 'Feature Bits']
]);

const FIELD_LABELS = new Map([
    ['version', 'Version'],
    ['fallback_address', 'Fall Back Address'],
    ['public_key', 'Public Key'],
    ['short_channel_id', 'Short Channel Id'],
    ['fee_base_msat', 'Fee Base Msat'],
    ['fee_proportional_millionths', 'Fee Proportional Millimonths'],
    ['cltv_expiry_delta', 'CLTV Expiry Delta'],
    ['r', 'R value'],
    ['s', 'S value'],
    ['recovery_flag', 'Recovery Flag']
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
    if (BOLT12_PREFIXES.has(prefix)) {
        throw new Error('Not yet supported: bolt12 ' + BOLT12_PREFIXES.get(prefix) + ' decoding');
    }
    throw new Error('Malformed request: unknown prefix');
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
    let amount = Number.isNaN(btc) ? 'any payment amount' : btc;
    rows.push({ label: 'Amount', value: toFixed(amount) + ' BTC' });

    rows.push({ label: 'Date', value: epochToDate(decoded.data.time_stamp) });

    let tags = decoded.data.tags;
    for (const tag of tags) {
        switch (tag.type) {
            case 'f':
            case 'r':
                rows.push({ label: BOLT11_TAG_LABELS.get('r'), sub: subRows(tag.value) });
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
                rows.push({ label: BOLT11_TAG_LABELS.get(tag.type), value: tag.value });
                break;
        }
    }

    if (!tags.some(tag => tag.type === 'x')) {
        rows.push({ label: BOLT11_TAG_LABELS.get('x'), value: 3600 + ' seconds' });
    }
    if (!tags.some(tag => tag.type === 'c')) {
        rows.push({ label: BOLT11_TAG_LABELS.get('c'), value: 9 });
    }

    rows.push({ label: 'Signature', sub: subRows(decoded.data.signature) });
    rows.push({ label: 'Signing Data', value: decoded.data.signing_data });
    rows.push({ label: 'Checksum', value: decoded.checksum });

    return {
        kind: 'bolt11-invoice',
        prefix: prefix,
        sections: [{ title: 'Payment Info:', rows: rows }],
        raw: decoded
    };
}
