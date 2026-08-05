// BOLT 12 payer proof tests: partial merkle reconstruction and both signatures.

const { test, describe } = require('node:test');
const assert = require('node:assert');

const { load } = require('./load.js');
const VECTORS = require('./vectors/payer-proof.json');

const lndecode = load();

const hex = bytes => lndecode.byteArrayToHexString(bytes);
const bytes = string => lndecode.hexStringToByteArray(string);

const VALID = VECTORS.valid_vectors;
const INVALID = VECTORS.invalid_vectors;

function recordsOf(bech32) {
    return Array.from(lndecode.parseTlvStream(lndecode.bolt12ToBytes(bech32).bytes));
}

describe('the vendored suite', () => {
    test('has 5 valid and 23 invalid vectors', () => {
        assert.strictEqual(VALID.length, 5);
        assert.strictEqual(INVALID.length, 23);
    });

    test('every invalid vector names a distinct reason', () => {
        const reasons = INVALID.map(v => v.reason);
        assert.strictEqual(new Set(reasons).size, reasons.length);
    });
});

describe('tree shape agrees with the full-tree builder', () => {
    // reconstructRoot and merkleRoot must pair leaves identically, including the carry on
    // odd counts, or a fully-disclosed proof would rebuild a different root.
    for (let count = 1; count <= 20; count++) {
        test(`${count} leaf/leaves`, () => {
            const tlvs = [];
            for (let i = 0; i < count; i++) tlvs.push(bytes('01020' + (i % 10) + '0' + (i % 10)));
            const nodes = tlvs.map(tlv => lndecode.leafNode(tlv, tlvs[0]));
            assert.strictEqual(
                hex(lndecode.reconstructRoot(nodes.map(hash => ({ hash: hash })), [])),
                hex(lndecode.merkleRoot(tlvs)));
        });
    }
});

describe('valid vectors', () => {
    for (const vector of VALID) {
        describe(vector.name, () => {
            test('decodes', () => {
                assert.doesNotThrow(() => lndecode.decodePayerProof(vector.result.bech32));
            });

            test('rebuilds the published invoice merkle root', () => {
                const decoded = lndecode.decodePayerProof(vector.result.bech32);
                assert.strictEqual(decoded.invoice_merkle_root, vector.working.invoice_merkle_root);
            });

            test('rebuilds the published proof merkle root', () => {
                const decoded = lndecode.decodePayerProof(vector.result.bech32);
                assert.strictEqual(decoded.proof_merkle_root, vector.working.proof_merkle_root);
            });

            test('the rebuilt root matches the root of the full invoice', () => {
                // The invoice is disclosed in full here, so the reconstruction can be
                // checked against a tree built the ordinary way.
                const invoice = Array.from(lndecode.parseTlvStream(bytes(vector.input.invoice_hex)));
                const signed = invoice.filter(r => r.type < 240n || r.type > 1000n);
                assert.strictEqual(hex(lndecode.merkleRoot(signed.map(r => r.tlv))),
                    vector.working.invoice_merkle_root);
            });

            test('reports the preimage and payment hash', () => {
                const decoded = lndecode.decodePayerProof(vector.result.bech32);
                assert.strictEqual(decoded.payment_preimage, vector.input.preimage);
                assert.strictEqual(hex(lndecode.sha256(bytes(decoded.payment_preimage))),
                    decoded.payment_hash);
            });

            test('reports the payer and node ids the suite names', () => {
                const decoded = lndecode.decodePayerProof(vector.result.bech32);
                assert.strictEqual(decoded.payer_id, VECTORS.keys.invreq_payer_id.pubkey);
                assert.strictEqual(decoded.node_id, VECTORS.keys.invoice_node_id.pubkey);
            });

            test('counts the withheld fields', () => {
                const decoded = lndecode.decodePayerProof(vector.result.bech32);
                const omitted = vector.input.invoice_fields
                    .filter(f => !f.included && f.type !== 240).length;
                assert.strictEqual(decoded.withheld_count, omitted);
            });

            test('disclosed types match the vector', () => {
                const decoded = lndecode.decodePayerProof(vector.result.bech32);
                const expected = vector.input.invoice_fields
                    .filter(f => f.included && f.type !== 240)
                    .map(f => f.type);
                assert.deepStrictEqual(Array.from(decoded.disclosed_types), expected);
            });
        });
    }

    test('only with_note carries a note', () => {
        for (const vector of VALID) {
            const decoded = lndecode.decodePayerProof(vector.result.bech32);
            assert.strictEqual(decoded.note !== undefined, vector.name === 'with_note',
                vector.name);
        }
    });
});

describe('invalid vectors', () => {
    // Each vector must be rejected by the rule its name describes, not by some unrelated
    // check that happens to fire first.
    const EXPECTED = new Map([
        ['missing_invreq_payer_id', /missing invreq_payer_id/],
        ['missing_invoice_payment_hash', /missing invoice_payment_hash/],
        ['missing_invoice_node_id', /missing invoice_node_id/],
        ['missing_signature', /missing signature/],
        ['missing_proof_preimage', /missing proof_preimage/],
        ['missing_proof_missing_hashes', /missing proof_missing_hashes/],
        ['missing_proof_leaf_hashes', /missing proof_leaf_hashes/],
        ['missing_proof_signature', /missing proof_signature/],
        ['wrong_proof_preimage', /does not hash to invoice_payment_hash/],
        ['proof_omitted_tlvs_not_ascending', /must strictly increase/],
        ['proof_omitted_tlvs_contains_zero', /contains 0/],
        ['proof_omitted_tlvs_contains_signature_field', /entry 241 is outside/],
        ['proof_omitted_tlvs_contains_proof_field', /entry 1001 is outside/],
        ['proof_omitted_tlvs_contains_high_field', /entry 4000000000 is outside/],
        ['proof_omitted_tlvs_contains_included_tlv_field', /is the type of an included field/],
        ['proof_omitted_tlvs_not_sequential', /does not follow the previous entry/],
        ['proof_leaf_hashes_too_few', /proof_leaf_hashes has 2 hashes for 3 disclosed fields/],
        ['proof_leaf_hashes_too_many', /proof_leaf_hashes has 4 hashes for 3 disclosed fields/],
        ['proof_missing_hashes_too_few', /too few proof_missing_hashes/],
        ['proof_missing_hashes_too_many', /unused proof_missing_hashes/],
        ['wrong_invoice_signature', /signature does not verify against invoice_node_id/],
        ['wrong_proof_signature', /proof_signature does not verify against invreq_payer_id/],
        ['contains_invreq_metadata', /must not include invreq_metadata/]
    ]);

    test('every vector has an expected rejection reason', () => {
        assert.deepStrictEqual(INVALID.map(v => v.reason).sort(), [...EXPECTED.keys()].sort());
    });

    for (const vector of INVALID) {
        test(`rejects: ${vector.reason}`, () => {
            const expected = EXPECTED.get(vector.reason);
            assert.ok(expected, `no expected message for ${vector.reason}`);
            // instanceof would compare against this realm's Error, not the sandbox's.
            assert.throws(() => lndecode.decodePayerProof(vector.bech32),
                error => {
                    const message = String(error.message);
                    assert.match(message, /Malformed request/, vector.reason);
                    assert.match(message, expected, vector.reason);
                    return true;
                });
        });
    }
});

describe('reconstruction ordering', () => {
    // proof_missing_hashes are emitted post-order depth-first. Consuming them level by
    // level instead yields the same root only when the tree happens not to interleave
    // pulls across depths, which two of the five vectors do not.
    test('the pull order matters for at least one vector', () => {
        const roots = new Set();
        for (const vector of VALID) {
            roots.add(lndecode.decodePayerProof(vector.result.bech32).invoice_merkle_root);
        }
        assert.ok(roots.size >= 2, 'vectors should exercise more than one root');
    });

    test('too few missing hashes is an error', () => {
        assert.throws(() => lndecode.reconstructRoot([{ hash: bytes('00'.repeat(32)) }, {}], []),
            /too few proof_missing_hashes/i);
    });

    test('unused missing hashes is an error', () => {
        assert.throws(() => lndecode.reconstructRoot(
            [{ hash: bytes('00'.repeat(32)) }, { hash: bytes('11'.repeat(32)) }],
            [bytes('22'.repeat(32))]),
            /unused proof_missing_hashes/i);
    });

    test('an entirely omitted tree is an error', () => {
        assert.throws(() => lndecode.reconstructRoot([{}, {}], []), /every tlv .* omitted/i);
    });
});

describe('prefix handling', () => {
    test('an offer is not a payer proof', () => {
        const offers = require('./vectors/offers.json');
        const offer = offers.find(v => v.valid);
        assert.throws(() => lndecode.decodePayerProof(offer.bolt12), /expected an lnp/i);
    });

    test('the valid vectors all carry the lnp prefix', () => {
        for (const vector of VALID) {
            assert.strictEqual(lndecode.bolt12ToBytes(vector.result.bech32).prefix, 'lnp');
        }
    });
});

describe('field names', () => {
    test('every spec field is named and nothing is unknown', () => {
        for (const vector of VALID) {
            for (const record of lndecode.decodePayerProof(vector.result.bech32).raw_records) {
                assert.doesNotMatch(record.name, /^unknown_/,
                    `type ${record.type} in ${vector.name} is unnamed`);
            }
        }
    });

    test('the experimental range is labelled rather than named', () => {
        // full_disclosure carries type 3000000001, a self-assigned experimental field with
        // no spec name.
        const decoded = lndecode.decodePayerProof(
            VALID.find(v => v.name === 'full_disclosure').result.bech32);
        const experimental = Array.from(decoded.raw_records).filter(r => r.type >= 1000000000);
        assert.strictEqual(experimental.length, 1);
        assert.strictEqual(experimental[0].name, 'experimental_3000000001');
    });

    test('the signature fields are excluded from the proof tree', () => {
        for (const vector of VALID) {
            const records = recordsOf(vector.result.bech32);
            const signed = records.filter(r => r.type < 240n || r.type > 1000n);
            assert.strictEqual(hex(lndecode.merkleRoot(signed.map(r => r.tlv))),
                vector.working.proof_merkle_root, vector.name);
            assert.ok(records.some(r => r.type === 240n), 'signature should be present');
            assert.ok(records.some(r => r.type === 241n), 'proof_signature should be present');
        }
    });
});
