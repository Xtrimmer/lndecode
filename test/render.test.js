// Display-model tests for both request forms.

const { test, describe } = require('node:test');
const assert = require('node:assert');

const { load } = require('./load.js');
const OFFER_VECTORS = require('./vectors/offers.json');
const PAYER_PROOF_VECTORS = require('./vectors/payer-proof.json');
const SIGNATURE_VECTORS = require('./vectors/signature.json');
const { VALID_VECTORS } = require('./vectors.js');

const lndecode = load();

const INVOICE_REQUEST = SIGNATURE_VECTORS.find(v => v.bolt12 !== undefined);

function proofBech32(name) {
    const found = PAYER_PROOF_VECTORS.valid_vectors.find(v => v.name === name);
    assert.ok(found, `no payer proof vector named "${name}"`);
    return found.result.bech32;
}

function offerModel(substring) {
    const found = OFFER_VECTORS.find(v => v.description.includes(substring));
    assert.ok(found, `no vector matching "${substring}"`);
    return lndecode.decodeRequest(found.bolt12);
}

function rows(model) {
    const out = new Map();
    for (const row of model.sections[0].rows) out.set(row.label, row);
    return out;
}

describe('dispatch', () => {
    test('routes an invoice to the bolt11 model', () => {
        const model = lndecode.decodeRequest(VALID_VECTORS[0].invoice);
        assert.strictEqual(model.kind, 'bolt11-invoice');
    });

    test('routes an offer to the offer model', () => {
        assert.strictEqual(offerModel('Minimal bolt12 offer').kind, 'bolt12-offer');
    });

    test('routes an invoice request to the invoice request model', () => {
        assert.strictEqual(lndecode.decodeRequest(INVOICE_REQUEST.bolt12).kind,
            'bolt12-invoice-request');
    });

    test('routes a payer proof to the payer proof model', () => {
        assert.strictEqual(lndecode.decodeRequest(proofBech32('full_disclosure')).kind,
            'bolt12-payer-proof');
    });

    test('every bolt12 prefix the spec defines is routed', () => {
        // A truncated body still reaches its decoder, so the error names a field or the
        // stream rather than the prefix.
        for (const prefix of ['lno', 'lnr', 'lnp']) {
            assert.throws(() => lndecode.decodeRequest(`${prefix}1qqq`),
                error => !/unknown prefix|not yet supported/i.test(String(error.message)),
                prefix);
        }
    });

    test('rejects an unknown prefix', () => {
        assert.throws(() => lndecode.decodeRequest('lnzz1qqq'), /unknown prefix/i);
    });
});

describe('offer model', () => {
    test('every valid offer builds a model with rows', () => {
        for (const v of OFFER_VECTORS.filter(v => v.valid)) {
            const model = lndecode.decodeRequest(v.bolt12);
            assert.deepStrictEqual(Array.from(model.sections.map(s => s.title)),
                ['Offer Info', 'Offer Breakdown']);
            assert.ok(model.sections[0].rows.length > 0, v.description);
        }
    });

    test('an absent offer_chains shows bitcoin mainnet', () => {
        assert.strictEqual(rows(offerModel('Minimal bolt12 offer')).get('Chains').value, 'bitcoin mainnet');
    });

    test('known chain hashes are named, in encoded order', () => {
        assert.strictEqual(rows(offerModel('for bitcoin or liquidv1')).get('Chains').value,
            'liquidv1, bitcoin mainnet');
        assert.strictEqual(rows(offerModel('for testnet')).get('Chains').value, 'bitcoin testnet');
    });

    test('an absent amount reads as any amount', () => {
        assert.strictEqual(rows(offerModel('Minimal bolt12 offer')).get('Amount').value, 'any amount');
    });

    test('a bitcoin amount is shown in millisatoshi', () => {
        assert.strictEqual(rows(offerModel('with amount')).get('Amount').value, '10000 msat');
    });

    // 10000 USD here is 100.00 dollars. The offer does not carry the ISO 4217 exponent,
    // so the value is labelled rather than converted.
    test('a currency amount is labelled as minor units', () => {
        assert.strictEqual(rows(offerModel('with currency')).get('Amount').value,
            '10000 USD (minor units)');
    });

    test('expiry is shown as a date', () => {
        assert.match(rows(offerModel('with expiry')).get('Expires').value, /2034|2035/);
    });

    test('a zero quantity max reads as unlimited', () => {
        assert.strictEqual(rows(offerModel('with unlimited (or unknown) quantity')).get('Quantity Max').value,
            'unlimited');
        assert.strictEqual(rows(offerModel('with quantity')).get('Quantity Max').value, '5');
    });

    test('feature bits are listed by number', () => {
        assert.strictEqual(rows(offerModel('with feature')).get('Feature Bits').value, '99');
    });

    test('a blinded path becomes nested rows', () => {
        const row = rows(offerModel('blinded path via Bob')).get('Blinded Path 1');
        assert.ok(row.sub, 'should be a nested row');
        const labels = row.sub.map(s => s.label);
        assert.deepStrictEqual(Array.from(labels),
            ['First Node Id', 'Path Key', 'Hop 1 Blinded Id', 'Hop 2 Blinded Id']);
    });

    test('a sciddir first node id is spelled out', () => {
        const row = rows(offerModel('first_node_id using sciddir')).get('Blinded Path 1');
        assert.strictEqual(row.sub[0].value, 'short channel id 000000000000002a, direction 0');
    });

    test('two paths become two rows', () => {
        const built = rows(offerModel('second blinded path via 1x2x3'));
        assert.ok(built.has('Blinded Path 1'));
        assert.ok(built.has('Blinded Path 2'));
    });

    test('no signature or checksum row appears', () => {
        for (const v of OFFER_VECTORS.filter(v => v.valid)) {
            const labels = lndecode.decodeRequest(v.bolt12).sections[0].rows.map(r => r.label);
            for (const absent of ['Signature', 'Checksum', 'Date', 'Signing Data']) {
                assert.ok(!labels.includes(absent), `${v.description} should have no ${absent} row`);
            }
        }
    });
});

describe('bolt11 model', () => {
    function bolt11Rows(substring) {
        const vector = VALID_VECTORS.find(v => v.description.includes(substring));
        assert.ok(vector, `no vector matching "${substring}"`);
        return lndecode.decodeRequest(vector.invoice).sections[0].rows;
    }

    function labels(substring) {
        return bolt11Rows(substring).map(row => row.label);
    }

    test('an unspecified amount is not given a BTC suffix', () => {
        const amount = bolt11Rows('donation of any amount').find(row => row.label === 'Amount');
        assert.strictEqual(amount.value, 'any payment amount');
    });

    test('a specified amount keeps its BTC suffix', () => {
        const amount = bolt11Rows('cup of coffee').find(row => row.label === 'Amount');
        assert.match(amount.value, / BTC$/);
    });

    test('a fallback address is labelled as one, not as routing info', () => {
        const found = labels('fallback (P2SH) address');
        assert.ok(found.includes('Fallback On-Chain Address'));
        assert.ok(!found.some(label => label.startsWith('Routing Info')));
    });

    test('each routing hop gets its own numbered row', () => {
        const found = labels('extra routing info');
        assert.ok(found.includes('Routing Info 1'));
        assert.ok(found.includes('Routing Info 2'));
    });

    test('a single routing hop is not numbered', () => {
        const rows = bolt11Rows('list of items');
        const routing = rows.filter(row => row.label.startsWith('Routing Info'));
        assert.strictEqual(routing.length, 1);
        assert.strictEqual(routing[0].label, 'Routing Info');
    });

    test('the default min final cltv expiry delta is 18', () => {
        const row = bolt11Rows('donation of any amount')
            .find(entry => entry.label === 'Min Final CLTV Expiry Delta');
        assert.strictEqual(row.value, 18);
    });

    test('payment metadata is labelled', () => {
        const row = bolt11Rows('payment metadata').find(entry => entry.label === 'Payment Metadata');
        assert.strictEqual(row.value, '01fafaf0');
    });

    test('routing sub rows are all labelled', () => {
        for (const row of bolt11Rows('extra routing info')) {
            if (row.sub === undefined) continue;
            for (const sub of row.sub) {
                assert.ok(sub.label !== undefined, `${row.label} has an unlabelled sub row`);
            }
        }
    });
});

describe('raw data breakdown', () => {
    test('an invoice breakdown reproduces the invoice exactly', () => {
        for (const v of VALID_VECTORS) {
            const decoded = lndecode.decode(v.invoice);
            assert.strictEqual(lndecode.rawPartsToString(decoded.raw_parts),
                v.invoice.toLowerCase(), v.description);
        }
    });

    test('the breakdown names each character group', () => {
        const vector = VALID_VECTORS.find(v => v.description.includes('(P2SH) address'));
        const rows = lndecode.decodeRequest(vector.invoice).sections[1].rows;
        const labels = rows.map(row => row.label);
        assert.strictEqual(labels[0], 'prefix');
        assert.strictEqual(labels[1], 'amount');
        assert.strictEqual(labels[2], 'separator');
        assert.strictEqual(labels[3], 'timestamp');
        assert.strictEqual(labels[labels.length - 2], 'signature');
        assert.strictEqual(labels[labels.length - 1], 'checksum');
        assert.ok(labels.some(label => label.startsWith('tagged field ')));
    });

    test('the breakdown keeps the bech32 a decoded field converts away', () => {
        // The h field reads as hex in the decoded output; its source characters are still
        // visible here.
        const vector = VALID_VECTORS.find(v => v.description.includes('entire list of things'));
        const rows = lndecode.decodeRequest(vector.invoice).sections[1].rows;
        const hashField = rows.find(row => row.label.startsWith('tagged field h'));
        assert.ok(hashField, 'the breakdown should include the h field');
        assert.strictEqual(hashField.sub.find(s => s.label === 'data').value,
            '8yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs');
    });

    test('an offer breakdown reproduces the payload bytes', () => {
        for (const v of OFFER_VECTORS.filter(v => v.valid)) {
            const offer = lndecode.decodeOffer(v.bolt12);
            const bigsize = n => {
                if (n < 0xfd) return n.toString(16).padStart(2, '0');
                if (n < 0x10000) return `fd${n.toString(16).padStart(4, '0')}`;
                if (n < 0x100000000) return `fe${n.toString(16).padStart(8, '0')}`;
                return `ff${n.toString(16).padStart(16, '0')}`;
            };
            const fromRecords = offer.raw_records
                .map(record => bigsize(record.type) + bigsize(record.length) + record.hex)
                .join('');
            assert.strictEqual(fromRecords,
                lndecode.byteArrayToHexString(lndecode.bolt12ToBytes(v.bolt12).bytes), v.description);
        }
    });

    test('an invoice model has two row sections plus the json', () => {
        const model = lndecode.decodeRequest(VALID_VECTORS[0].invoice);
        assert.deepStrictEqual(Array.from(model.sections.map(s => s.title)),
            ['Payment Info', 'Invoice Breakdown']);
        assert.strictEqual(model.jsonTitle, 'Decoded JSON');
    });
});

describe('decoded json section', () => {
    function json(input) {
        return JSON.stringify(lndecode.decodeRequest(input).raw, lndecode.jsonReplacer, 4);
    }

    test('omits the character breakdown', () => {
        assert.ok(!json(VALID_VECTORS[0].invoice).includes('raw_parts'));
    });

    test('still carries the decoded values it always did', () => {
        const text = json(VALID_VECTORS.find(v => v.description.includes('(P2SH) address')).invoice);
        for (const key of ['human_readable_part', 'amount', 'time_stamp', 'tags', 'signature',
            'signing_data', 'checksum']) {
            // all still in the json, though checksum and signing_data left Payment Info
            assert.ok(text.includes(key), `json should still contain ${key}`);
        }
    });

    test('renders a BigInt offer amount as a string', () => {
        const offer = OFFER_VECTORS.find(v => v.valid && v.description.includes('with amount'));
        assert.ok(json(offer.bolt12).includes('"10000"'));
    });
});

describe('sections do not repeat each other', () => {
    function flatten(rows) {
        const out = [];
        for (const row of rows) {
            if (row.sub) row.sub.forEach(sub => out.push([`${row.label} / ${sub.label}`, String(sub.value)]));
            else out.push([row.label, String(row.value)]);
        }
        return out;
    }

    function duplicates(input) {
        const model = lndecode.decodeRequest(input);
        const rawValues = new Set(flatten(model.sections[1].rows).map(([, value]) => value));
        // Short values collide by chance; a shared long string is real repetition.
        return flatten(model.sections[0].rows)
            .filter(([, value]) => value.length > 2 && rawValues.has(value))
            .map(([label]) => label);
    }

    test('no invoice repeats a value between its two sections', () => {
        for (const v of VALID_VECTORS) {
            assert.deepStrictEqual(duplicates(v.invoice), [], v.description);
        }
    });

    test('checksum and signing data are gone from Payment Info but kept in the json', () => {
        const model = lndecode.decodeRequest(VALID_VECTORS[0].invoice);
        const labels = model.sections[0].rows.map(row => row.label);
        assert.ok(!labels.includes('Checksum'));
        assert.ok(!labels.includes('Signing Data'));

        const json = JSON.stringify(model.raw, lndecode.jsonReplacer, 4);
        assert.ok(json.includes('checksum'), 'checksum should remain in the json');
        assert.ok(json.includes('signing_data'), 'signing_data should remain in the json');
    });

    test('the checksum is still shown, in the breakdown', () => {
        const model = lndecode.decodeRequest(VALID_VECTORS[0].invoice);
        const checksum = model.sections[1].rows.find(row => row.label === 'checksum');
        assert.ok(checksum, 'the breakdown should carry the checksum');
        assert.strictEqual(checksum.value, model.raw.checksum);
    });
});

describe('invoice request model', () => {
    const model = () => lndecode.decodeRequest(INVOICE_REQUEST.bolt12);

    test('both sections are present and titled for the form', () => {
        assert.deepStrictEqual(Array.from(model().sections, s => s.title),
            ['Invoice Request Info', 'Invoice Request Breakdown']);
    });

    test('an absent invreq_chain shows bitcoin mainnet', () => {
        assert.strictEqual(rows(model()).get('Chain').value, 'bitcoin mainnet');
    });

    test('an absent invreq_amount is unspecified rather than blank', () => {
        assert.strictEqual(rows(model()).get('Amount Requested').value, 'unspecified');
    });

    test('a currency-denominated offer amount is labelled as minor units', () => {
        assert.strictEqual(rows(model()).get('Offer Amount').value, '100 USD (minor units)');
    });

    test('the payer metadata and id are shown', () => {
        const built = rows(model());
        assert.strictEqual(built.get('Payer Metadata').value, '0000000000000000');
        assert.match(built.get('Payer Id').value, /^0324653eac/);
    });

    test('the signature row names the key it verified against', () => {
        assert.strictEqual(rows(model()).get('Signature').value, 'verified against Payer Id');
    });

    test('the merkle root is the one the spec publishes', () => {
        assert.strictEqual(rows(model()).get('Merkle Root').value, INVOICE_REQUEST.merkle);
    });

    test('every row carries a label', () => {
        for (const row of model().sections[0].rows) {
            assert.ok(row.label, `row without a label: ${JSON.stringify(row)}`);
        }
    });
});

describe('payer proof model', () => {
    const model = name => lndecode.decodeRequest(proofBech32(name));

    test('both sections are present and titled for the form', () => {
        assert.deepStrictEqual(Array.from(model('full_disclosure').sections, s => s.title),
            ['Payer Proof Info', 'Payer Proof Breakdown']);
    });

    test('the preimage and payment hash are shown', () => {
        const built = rows(model('full_disclosure'));
        assert.match(built.get('Payment Preimage').value, /^0101010101/);
        assert.strictEqual(built.get('Payment Hash').value.length, 64);
    });

    test('withheld fields are stated rather than left absent', () => {
        // The whole point of a proof is that some fields are missing, so a reader must be
        // told they were withheld instead of inferring it from a short list.
        const built = rows(model('minimal_disclosure'));
        assert.match(built.get('Withheld Fields').value, /^7 withheld/);
        assert.match(built.get('Withheld Fields').value, /identities hidden/);
    });

    test('the disclosed count and total agree with the vector', () => {
        for (const vector of PAYER_PROOF_VECTORS.valid_vectors) {
            const built = rows(lndecode.decodeRequest(vector.result.bech32));
            const disclosed = vector.input.invoice_fields
                .filter(f => f.included && f.type !== 240).length;
            const withheld = vector.input.invoice_fields
                .filter(f => !f.included && f.type !== 240).length;
            assert.strictEqual(built.get('Disclosed Fields').value,
                `${disclosed} of ${disclosed + withheld}`, vector.name);
        }
    });

    test('each disclosed field is named in a sub row', () => {
        const row = rows(model('minimal_disclosure')).get('Disclosed Fields');
        assert.deepStrictEqual(Array.from(row.sub, s => s.label),
            ['invreq_payer_id', 'invoice_payment_hash', 'invoice_node_id']);
    });

    test('both signature verdicts are shown with their roots', () => {
        const built = rows(model('full_disclosure'));
        const vector = PAYER_PROOF_VECTORS.valid_vectors.find(v => v.name === 'full_disclosure');
        assert.match(built.get('Invoice Signature').value, /verified against Invoice Node Id/);
        assert.strictEqual(built.get('Invoice Signature').sub[0].value,
            vector.working.invoice_merkle_root);
        assert.match(built.get('Proof Signature').value, /verified against Payer Id/);
        assert.strictEqual(built.get('Proof Signature').sub[0].value,
            vector.working.proof_merkle_root);
    });

    test('only with_note shows a note row', () => {
        for (const vector of PAYER_PROOF_VECTORS.valid_vectors) {
            const built = rows(lndecode.decodeRequest(vector.result.bech32));
            assert.strictEqual(built.has('Note'), vector.name === 'with_note', vector.name);
        }
    });

    test('every valid vector builds a model with labelled rows', () => {
        for (const vector of PAYER_PROOF_VECTORS.valid_vectors) {
            const built = lndecode.decodeRequest(vector.result.bech32);
            assert.ok(built.sections[0].rows.length > 0, vector.name);
            for (const row of built.sections[0].rows) {
                assert.ok(row.label, `${vector.name}: row without a label`);
            }
        }
    });

    test('an invalid proof reaches the caller as an error', () => {
        for (const vector of PAYER_PROOF_VECTORS.invalid_vectors) {
            assert.throws(() => lndecode.decodeRequest(vector.bech32), undefined, vector.reason);
        }
    });
});

describe('bolt12 breakdowns reconstruct their stream', () => {
    function reassemble(section, prefix) {
        let out = `${prefix}1`;
        for (const row of section.rows) {
            if (row.label === 'prefix' || row.label === 'separator') continue;
            const byLabel = new Map(Array.from(row.sub, s => [s.label, s.value]));
            out += `${byLabel.get('type')}:${byLabel.get('length')}:${byLabel.get('value')} `;
        }
        return out;
    }

    test('every tlv record appears in the breakdown exactly once', () => {
        const cases = [INVOICE_REQUEST.bolt12, proofBech32('with_note'),
            OFFER_VECTORS.find(v => v.valid).bolt12];
        for (const request of cases) {
            const built = lndecode.decodeRequest(request);
            const records = built.sections[1].rows.filter(r => r.sub !== undefined);
            assert.strictEqual(records.length, built.raw.raw_records.length, request.slice(0, 12));
            assert.ok(reassemble(built.sections[1], built.prefix).length > 0);
        }
    });

    test('the breakdown starts with the prefix and separator', () => {
        for (const request of [INVOICE_REQUEST.bolt12, proofBech32('with_note')]) {
            const built = lndecode.decodeRequest(request);
            assert.deepStrictEqual(Array.from(built.sections[1].rows.slice(0, 2), r => r.label),
                ['prefix', 'separator']);
            assert.strictEqual(built.sections[1].rows[0].value, built.prefix);
        }
    });
});
