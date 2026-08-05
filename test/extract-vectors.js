// Re-vendors every test vector from the lightning/bolts and bitcoin/bips repositories.
//
//   npm run vectors
//
// Writes:
//   test/vectors.js                     BOLT 11 invoices, parsed out of the spec prose
//   test/vectors/format-string.json     BOLT 12 string format
//   test/vectors/offers.json            BOLT 12 offers
//   test/vectors/signature.json         BOLT 12 merkle trees and signature hashes
//   test/vectors/bip340.json            BIP-340 Schnorr, from the bitcoin/bips csv
//   test/vectors/bigsize.json           BigSize, from a fenced block in BOLT 1

const fs = require('fs');
const path = require('path');

const RAW = 'https://raw.githubusercontent.com/lightning/bolts/master/';
const BIPS_RAW = 'https://raw.githubusercontent.com/bitcoin/bips/master/';
const OUT_DIR = path.join(__dirname, 'vectors');

async function fetchFrom(base, file) {
    const res = await fetch(base + file);
    if (!res.ok) throw new Error(`fetch ${file} failed: ${res.status} ${res.statusText}`);
    return res.text();
}

async function fetchText(file) {
    return fetchFrom(RAW, file);
}

// --- BOLT 11: a blockquote heading followed by a blockquote line holding one long
// token -----------------------------------------------------------------------

// The blockquote prefix on the invoice line is optional: at least one vector in the
// spec omits it.
function collectInvoices(lines) {
    const out = [];
    let headings = 0;
    let description = '';
    for (const line of lines) {
        const heading = line.match(/^>\s*#+\s*(.+?)\s*$/);
        if (heading) { description = heading[1]; headings++; continue; }
        const invoice = line.match(/^>?\s*([0-9A-Za-z]{40,})\s*$/);
        if (invoice) out.push({ description, invoice: invoice[1] });
    }
    return { vectors: out, headings };
}

function serialize(name, vectors) {
    const body = vectors.map(v =>
        `    {\n` +
        `        description: ${JSON.stringify(v.description)},\n` +
        `        invoice: ${JSON.stringify(v.invoice)}\n` +
        `    }`
    ).join(',\n');
    return `const ${name} = [\n${body}\n];\n`;
}

async function writeBolt11() {
    const source = '11-payment-encoding.md';
    const lines = (await fetchText(source)).split('\n');

    const splitAt = lines.findIndex(l => /^#\s*Examples of Invalid Invoices/.test(l));
    if (splitAt === -1) throw new Error('could not locate "Examples of Invalid Invoices" heading');

    const validPart = collectInvoices(lines.slice(0, splitAt));
    const invalidPart = collectInvoices(lines.slice(splitAt));
    const valid = validPart.vectors;
    const invalid = invalidPart.vectors;
    if (!valid.length || !invalid.length) {
        throw new Error(`extraction looks wrong: ${valid.length} valid, ${invalid.length} invalid`);
    }
    // Every described example should yield an invoice. A shortfall means a vector was
    // formatted in a way the patterns above do not match.
    for (const [name, part] of [['valid', validPart], ['invalid', invalidPart]]) {
        if (part.vectors.length < part.headings) {
            throw new Error(`${name}: ${part.headings} headings but only ${part.vectors.length} `
                + `invoices extracted; a vector is being dropped`);
        }
    }

    const header =
        `// GENERATED FILE - do not edit by hand.\n` +
        `//\n` +
        `// BOLT 11 test vectors extracted from the spec.\n` +
        `// Source: ${RAW}${source}\n` +
        `// Regenerate: npm run vectors\n` +
        `//\n` +
        `// VALID_VECTORS   - a conforming reader MUST decode these.\n` +
        `// INVALID_VECTORS - a conforming reader MUST reject these.\n\n`;

    fs.writeFileSync(path.join(__dirname, 'vectors.js'),
        header +
        serialize('VALID_VECTORS', valid) + '\n' +
        serialize('INVALID_VECTORS', invalid) + '\n' +
        `module.exports = { VALID_VECTORS, INVALID_VECTORS };\n`
    );
    return `vectors.js: ${valid.length} valid, ${invalid.length} invalid`;
}

// --- BOLT 12: vendored verbatim ---------------------------------------------

async function writeJson(source, outName, expected) {
    const parsed = JSON.parse(await fetchText(source));
    if (!Array.isArray(parsed) || parsed.length < expected) {
        throw new Error(`${source} looks wrong: ${parsed.length} entries, expected at least ${expected}`);
    }
    fs.writeFileSync(path.join(OUT_DIR, outName), JSON.stringify(parsed, null, 2) + '\n');
    return `${outName}: ${parsed.length} vectors`;
}

// --- BigSize: a fenced json block inside BOLT 1 Appendix A ------------------

async function writeBigSize() {
    const source = '01-messaging.md';
    let text = await fetchText(source);
    const appendix = text.indexOf('## Appendix A: BigSize Test Vectors');
    if (appendix === -1) throw new Error('could not locate BigSize appendix');

    // Bounded at the next appendix.
    const end = text.indexOf('## Appendix B', appendix);
    if (end === -1) throw new Error('could not locate the appendix after BigSize');
    text = text.slice(appendix, end);

    // Each fenced json block is one suite. Values are quoted so the exact digits
    // survive parsing.
    const blocks = [...text.matchAll(/```json\n([\s\S]*?)```/g)]
        .map(m => JSON.parse(m[1].replace(/"value":\s*(\d+)/g, '"value": "$1"')));
    if (!blocks.length) throw new Error('no fenced json blocks in the BigSize appendix');

    const merged = [].concat(...blocks);
    if (!merged.every(v => typeof v.value === 'string')) {
        throw new Error('BigSize values should all have been quoted');
    }
    fs.writeFileSync(path.join(OUT_DIR, 'bigsize.json'), JSON.stringify(merged, null, 2) + '\n');
    return `bigsize.json: ${merged.length} vectors from ${blocks.length} block(s)`;
}

// --- BIP-340: the Schnorr suite BOLT 12 signatures are defined against ----------

async function writeBip340() {
    const source = 'bip-0340/test-vectors.csv';
    // The csv uses CRLF, which would otherwise leave a carriage return on each last field.
    const lines = (await fetchFrom(BIPS_RAW, source)).trim().split(/\r?\n/);
    const columns = lines[0].split(',');
    const wanted = ['index', 'public key', 'message', 'signature', 'verification result', 'comment'];
    const at = wanted.map(name => {
        const index = columns.indexOf(name);
        if (index === -1) throw new Error(`BIP-340 csv has no "${name}" column`);
        return index;
    });

    const vectors = lines.slice(1).map(line => {
        const fields = line.split(',');
        if (fields.length !== columns.length) {
            throw new Error(`BIP-340 csv row has ${fields.length} fields, expected ${columns.length}`);
        }
        const [index, publicKey, message, signature, result, comment] = at.map(i => fields[i]);
        if (result !== 'TRUE' && result !== 'FALSE') {
            throw new Error(`BIP-340 row ${index} has an unexpected result "${result}"`);
        }
        return {
            index: Number(index),
            public_key: publicKey.toLowerCase(),
            message: message.toLowerCase(),
            signature: signature.toLowerCase(),
            valid: result === 'TRUE',
            comment: comment
        };
    });

    if (vectors.length < 19) {
        throw new Error(`BIP-340 csv looks wrong: ${vectors.length} vectors`);
    }
    if (!vectors.some(v => v.valid) || !vectors.some(v => !v.valid)) {
        throw new Error('BIP-340 vectors should include both valid and invalid cases');
    }
    fs.writeFileSync(path.join(OUT_DIR, 'bip340.json'), JSON.stringify(vectors, null, 2) + '\n');
    const valid = vectors.filter(v => v.valid).length;
    return `bip340.json: ${vectors.length} vectors, ${valid} valid, ${vectors.length - valid} invalid`;
}

(async () => {
    fs.mkdirSync(OUT_DIR, { recursive: true });
    const results = [
        await writeBolt11(),
        await writeJson('bolt12/format-string-test.json', 'format-string.json', 12),
        await writeJson('bolt12/offers-test.json', 'offers.json', 50),
        await writeJson('bolt12/signature-test.json', 'signature.json', 4),
        await writeBip340(),
        await writeBigSize()
    ];
    for (const r of results) console.log('  ' + r);
})();
