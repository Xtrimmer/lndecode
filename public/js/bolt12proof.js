// BOLT 12 payer proof decoding: partial merkle reconstruction and two signatures.

const INVREQ_METADATA_TYPE = 0n;
const SIGNATURE_TYPE = 240n;
const PROOF_SIGNATURE_TYPE = 241n;
const PROOF_PREIMAGE_TYPE = 1001n;
const PROOF_OMITTED_TLVS_TYPE = 1002n;
const PROOF_MISSING_HASHES_TYPE = 1003n;
const PROOF_LEAF_HASHES_TYPE = 1004n;
const PROOF_NOTE_TYPE = 1005n;

const PREIMAGE_LENGTH = 32;
const HASH_LENGTH = 32;

// Signature TLV types are excluded from the tree they sign.
const SIGNATURE_RANGE_START = 240n;
const SIGNATURE_RANGE_END = 1000n;

// The ranges a proof's own tree covers: the invoice fields and the custom range above them.
const PROOF_TREE_RANGES = [[1n, 239n], [1000000000n, 3999999999n]];

const MARKER_CUSTOM_RANGE_START = 1000000000n;
const MARKER_LOW_RANGE_END = 239n;

const PROOF_FIELD_NAMES = new Map([
    [0n, 'invreq_metadata'],
    [2n, 'offer_chains'], [4n, 'offer_metadata'], [6n, 'offer_currency'], [8n, 'offer_amount'],
    [10n, 'offer_description'], [12n, 'offer_features'], [14n, 'offer_absolute_expiry'],
    [16n, 'offer_paths'], [18n, 'offer_issuer'], [20n, 'offer_quantity_max'],
    [22n, 'offer_issuer_id'],
    [80n, 'invreq_chain'], [82n, 'invreq_amount'], [84n, 'invreq_features'],
    [86n, 'invreq_quantity'], [88n, 'invreq_payer_id'], [89n, 'invreq_payer_note'],
    [90n, 'invreq_paths'], [91n, 'invreq_bip_353_name'],
    [160n, 'invoice_paths'], [162n, 'invoice_blindedpay'], [164n, 'invoice_created_at'],
    [166n, 'invoice_relative_expiry'], [168n, 'invoice_payment_hash'], [170n, 'invoice_amount'],
    [172n, 'invoice_fallbacks'], [174n, 'invoice_features'], [176n, 'invoice_node_id'],
    [240n, 'signature'], [241n, 'proof_signature'],
    [1001n, 'proof_preimage'], [1002n, 'proof_omitted_tlvs'], [1003n, 'proof_missing_hashes'],
    [1004n, 'proof_leaf_hashes'], [1005n, 'proof_note']
]);

const REQUIRED_PROOF_TYPES = [
    [88n, 'invreq_payer_id'],
    [168n, 'invoice_payment_hash'],
    [176n, 'invoice_node_id'],
    [240n, 'signature'],
    [241n, 'proof_signature'],
    [1001n, 'proof_preimage'],
    [1003n, 'proof_missing_hashes'],
    [1004n, 'proof_leaf_hashes']
];

// Types at or above a billion are the self-assigned experimental range, so they have no
// spec name to look up.
function proofFieldName(type) {
    const name = PROOF_FIELD_NAMES.get(type);
    if (name !== undefined) return name;
    if (type >= MARKER_CUSTOM_RANGE_START) return `experimental_${type.toString()}`;
    return `unknown_${type.toString()}`;
}

function isSignatureType(type) {
    return type >= SIGNATURE_RANGE_START && type <= SIGNATURE_RANGE_END;
}

function inProofTreeRanges(type) {
    return PROOF_TREE_RANGES.some(range => type >= range[0] && type <= range[1]);
}

// Splits a value into 32-byte hashes, requiring an exact multiple.
function splitHashes(bytes, what) {
    if (bytes.length === 0 || bytes.length % HASH_LENGTH !== 0) {
        throw new Error(`Malformed request: ${what} must be a whole number of 32-byte hashes`);
    }
    const hashes = [];
    for (let at = 0; at < bytes.length; at += HASH_LENGTH) {
        hashes.push(bytes.slice(at, at + HASH_LENGTH));
    }
    return hashes;
}

function readMarkers(bytes) {
    const reader = byteReader(bytes);
    const markers = [];
    while (reader.remaining() > 0) {
        markers.push(reader.readBigSize('proof_omitted_tlvs entry'));
    }
    return markers;
}

// A marker hides a real type number while preserving order. Each is one greater than the
// previous marker, one greater than an included type, or the start of the custom range
// after 239.
function requireValidMarkers(markers, includedTypes) {
    let previous = 0n;
    for (const marker of markers) {
        if (marker === 0n) {
            throw new Error('Malformed request: proof_omitted_tlvs contains 0');
        }
        if (marker <= previous) {
            throw new Error('Malformed request: proof_omitted_tlvs must strictly increase');
        }
        if (!inProofTreeRanges(marker)) {
            throw new Error(`Malformed request: proof_omitted_tlvs entry ${marker} is outside 1 to 239 and 1000000000 to 3999999999`);
        }
        if (includedTypes.has(marker)) {
            throw new Error(`Malformed request: proof_omitted_tlvs entry ${marker} is the type of an included field`);
        }
        const sequential = marker === previous + 1n;
        const afterIncluded = includedTypes.has(marker - 1n);
        const entersCustomRange = marker === MARKER_CUSTOM_RANGE_START
            && previous === MARKER_LOW_RANGE_END;
        if (!sequential && !afterIncluded && !entersCustomRange) {
            throw new Error(`Malformed request: proof_omitted_tlvs entry ${marker} does not follow the previous entry or an included field`);
        }
        previous = marker;
    }
}

// Rebuilds the invoice's merkle root. Present fields hash their own bytes against a nonce
// supplied by the proof, because the nonce tag needs invreq_metadata, which is absent.
function reconstructInvoiceRoot(treeRecords, leafHashes, missingHashes, markers) {
    if (leafHashes.length !== treeRecords.length) {
        throw new Error(`Malformed request: proof_leaf_hashes has ${leafHashes.length} hashes for ${treeRecords.length} disclosed fields`);
    }

    const leaves = treeRecords.map((record, at) => ({
        key: record.type,
        hash: branchNode(leafHash(record.tlv), leafHashes[at])
    }));
    // Type 0 is always omitted, so it is implied rather than carried in the markers.
    const absent = [INVREQ_METADATA_TYPE].concat(markers).map(key => ({ key }));

    const slots = leaves.concat(absent);
    slots.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    return reconstructRoot(slots, missingHashes);
}

function decodePayerProof(request) {
    const split = bolt12ToBytes(request);
    if (split.prefix !== 'lnp') {
        throw new Error(`Malformed request: expected an lnp payer proof, got ${split.prefix}`);
    }

    const records = parseTlvStream(split.bytes);
    const byType = new Map(records.map(record => [record.type, record]));

    for (const [type, name] of REQUIRED_PROOF_TYPES) {
        if (!byType.has(type)) {
            throw new Error(`Malformed request: payer proof is missing ${name}`);
        }
    }
    if (byType.has(INVREQ_METADATA_TYPE)) {
        throw new Error('Malformed request: payer proof must not include invreq_metadata');
    }

    const preimage = byType.get(PROOF_PREIMAGE_TYPE).value;
    if (preimage.length !== PREIMAGE_LENGTH) {
        throw new Error('Malformed request: proof_preimage must be 32 bytes');
    }
    const paymentHash = byType.get(168n).value;
    if (byteArrayToHexString(sha256(preimage)) !== byteArrayToHexString(paymentHash)) {
        throw new Error('Malformed request: proof_preimage does not hash to invoice_payment_hash');
    }

    const treeRecords = records.filter(record => inProofTreeRanges(record.type));
    const includedTypes = new Set(treeRecords.map(record => record.type));
    const markers = byType.has(PROOF_OMITTED_TLVS_TYPE)
        ? readMarkers(byType.get(PROOF_OMITTED_TLVS_TYPE).value)
        : [];
    requireValidMarkers(markers, includedTypes);

    const leafHashes = splitHashes(byType.get(PROOF_LEAF_HASHES_TYPE).value, 'proof_leaf_hashes');
    const missingHashes = splitHashes(byType.get(PROOF_MISSING_HASHES_TYPE).value,
        'proof_missing_hashes');

    const invoiceRoot = reconstructInvoiceRoot(treeRecords, leafHashes, missingHashes, markers);
    const nodeId = byType.get(176n).value;
    const invoiceSighash = signatureHash('invoice', 'signature', invoiceRoot);
    if (!verifyBolt12Signature(byType.get(SIGNATURE_TYPE).value, invoiceSighash, nodeId)) {
        throw new Error('Malformed request: signature does not verify against invoice_node_id');
    }

    const payerId = byType.get(88n).value;
    const proofSigned = Array.from(records).filter(record => !isSignatureType(record.type));
    const proofRoot = merkleRoot(proofSigned.map(record => record.tlv));
    const proofSighash = signatureHash('payer_proof', 'proof_signature', proofRoot);
    if (!verifyBolt12Signature(byType.get(PROOF_SIGNATURE_TYPE).value, proofSighash, payerId)) {
        throw new Error('Malformed request: proof_signature does not verify against invreq_payer_id');
    }

    return {
        prefix: split.prefix,
        payment_preimage: byteArrayToHexString(preimage),
        payment_hash: byteArrayToHexString(paymentHash),
        payer_id: byteArrayToHexString(payerId),
        node_id: byteArrayToHexString(nodeId),
        note: byType.has(PROOF_NOTE_TYPE)
            ? bytesToUtf8String(byType.get(PROOF_NOTE_TYPE).value)
            : undefined,
        invoice_merkle_root: byteArrayToHexString(invoiceRoot),
        proof_merkle_root: byteArrayToHexString(proofRoot),
        disclosed_types: treeRecords.map(record => Number(record.type)),
        withheld_count: markers.length + 1,
        raw_records: Array.from(records).map(record => ({
            type: Number(record.type),
            name: proofFieldName(record.type),
            length: record.length,
            hex: byteArrayToHexString(record.value)
        }))
    };
}
