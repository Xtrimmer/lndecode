// BOLT 12 signature verification: BIP-340 Schnorr over the merkle root.

// The vendored secp256k1 ships hashes.sha256 unset and expects one supplied. The ECDSA
// paths pass prehash: false and supply their own digest; Schnorr hashes internally.
secp256k1.hashes.sha256 = message => new Uint8Array(sha256(message));

const BOLT12_SIGNATURE_LENGTH = 64;
const SIGNATURE_TLV_TYPE = 240n;

// BIP-340 keys are the 32-byte x coordinate. BOLT 12 carries 33-byte compressed points.
function xOnlyPoint(point) {
    if (point.length === 32) return Array.from(point);
    if (point.length === 33 && (point[0] === 0x02 || point[0] === 0x03)) {
        return Array.from(point).slice(1);
    }
    throw new Error('Malformed request: signing key is not a 33-byte compressed point');
}

function verifyBolt12Signature(signature, sighash, point) {
    if (signature.length !== BOLT12_SIGNATURE_LENGTH) {
        throw new Error(`Malformed request: signature must be ${BOLT12_SIGNATURE_LENGTH} bytes, got ${signature.length}`);
    }
    return secp256k1.schnorr.verify(
        new Uint8Array(signature),
        new Uint8Array(sighash),
        new Uint8Array(xOnlyPoint(point)));
}

// The signature field is excluded from the tree it signs.
function signedRecords(records) {
    return Array.from(records).filter(record => record.type !== SIGNATURE_TLV_TYPE);
}

// Rebuilds the merkle root over every record except the signature, tags it with the
// message name, and checks the signature against the given point.
function verifySignedStream(messageName, records, signature, point) {
    const signed = signedRecords(records);
    if (signed.length === 0) {
        throw new Error('Malformed request: nothing to verify the signature over');
    }
    const root = merkleRoot(signed.map(record => record.tlv));
    const sighash = signatureHash(messageName, 'signature', root);
    return verifyBolt12Signature(signature, sighash, point);
}
