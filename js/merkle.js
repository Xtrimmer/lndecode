// BOLT 12 merkle root and tagged hashes, over raw TLV records.

const LN_LEAF = textToByteArray('LnLeaf');
const LN_NONCE = textToByteArray('LnNonce');
const LN_BRANCH = textToByteArray('LnBranch');

// H(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg), per BIP-340.
function bolt12TaggedHash(tag, msg) {
    let tagHash = sha256(tag);
    return sha256(tagHash.concat(tagHash).concat(msg));
}

function compareBytes(a, b) {
    for (let i = 0; i < a.length && i < b.length; i++) {
        if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
}

// Reads the width of the leading BigSize of a raw TLV record and returns its bytes.
function tlvTypeBytes(tlv) {
    if (tlv.length === 0) {
        throw new Error('Malformed request: empty tlv record');
    }
    let first = tlv[0];
    let width = first < 0xfd ? 1 : first === 0xfd ? 3 : first === 0xfe ? 5 : 9;
    if (tlv.length < width) {
        throw new Error('Malformed request: truncated tlv type');
    }
    return tlv.slice(0, width);
}

// H("LnBranch", lesser || greater), ordered by value.
function branchNode(left, right) {
    let ordered = compareBytes(left, right) <= 0 ? left.concat(right) : right.concat(left);
    return bolt12TaggedHash(LN_BRANCH, ordered);
}

function leafHash(tlv) {
    return bolt12TaggedHash(LN_LEAF, tlv);
}

function nonceHash(tlv, firstTlv) {
    return bolt12TaggedHash(LN_NONCE.concat(firstTlv), tlvTypeBytes(tlv));
}

// Each TLV pairs its leaf with a nonce leaf, giving one node per record.
function leafNode(tlv, firstTlv) {
    return branchNode(leafHash(tlv), nonceHash(tlv, firstTlv));
}

// Combines a level pairwise, carrying an unpaired node up unchanged. Repeating this
// puts the deepest subtree on the lowest-order leaves.
function combineLevel(nodes) {
    let next = [];
    for (let i = 0; i < nodes.length; i += 2) {
        next.push(i + 1 < nodes.length ? branchNode(nodes[i], nodes[i + 1]) : nodes[i]);
    }
    return next;
}

// Every level of the tree, from the one-node-per-record base up to the single root.
// Within a level, the first floor(count / 2) nodes of the level above are its pairings
// and an odd final node is carried up unchanged.
function merkleLevels(tlvs) {
    if (tlvs.length === 0) {
        throw new Error('Malformed request: a merkle tree needs at least one tlv record');
    }
    let firstTlv = tlvs[0];
    let levels = [tlvs.map(tlv => leafNode(tlv, firstTlv))];
    while (levels[levels.length - 1].length > 1) {
        levels.push(combineLevel(levels[levels.length - 1]));
    }
    return levels;
}

// Takes the raw bytes of each TLV record, in stream order.
function merkleRoot(tlvs) {
    let levels = merkleLevels(tlvs);
    return levels[levels.length - 1][0];
}

// The tag is "lightning" || messagename || fieldname and the message is the merkle root.
function signatureHash(messageName, fieldName, root) {
    return bolt12TaggedHash(textToByteArray('lightning' + messageName + fieldName), root);
}
