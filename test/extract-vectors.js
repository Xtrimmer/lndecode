// Regenerates test/vectors.js from the BOLT 11 spec markdown.
//
//   node test/extract-vectors.js                    # fetch latest from lightning/bolts
//   node test/extract-vectors.js path/to/11-payment-encoding.md
//
// Vectors are vendored rather than fetched at test time so the suite runs
// offline and deterministically.

const fs = require('fs');
const path = require('path');

const SPEC_URL = 'https://raw.githubusercontent.com/lightning/bolts/master/11-payment-encoding.md';
const OUT = path.join(__dirname, 'vectors.js');

async function readSpec(arg) {
    if (arg) return { text: fs.readFileSync(arg, 'utf8'), source: arg };
    const res = await fetch(SPEC_URL);
    if (!res.ok) throw new Error(`fetch failed: ${res.status} ${res.statusText}`);
    return { text: await res.text(), source: SPEC_URL };
}

// Invoices appear as a blockquote line holding a single bech32-ish token,
// preceded by a blockquote heading that describes them.
function collect(lines) {
    const out = [];
    let description = '';
    for (const line of lines) {
        const heading = line.match(/^>\s*#+\s*(.+?)\s*$/);
        if (heading) { description = heading[1]; continue; }
        const invoice = line.match(/^>\s*([0-9A-Za-z]{40,})\s*$/);
        if (invoice) out.push({ description, invoice: invoice[1] });
    }
    return out;
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

(async () => {
    const arg = process.argv[2];
    const { text, source } = await readSpec(arg);
    const lines = text.split('\n');

    const splitAt = lines.findIndex(l => /^#\s*Examples of Invalid Invoices/.test(l));
    if (splitAt === -1) throw new Error('could not locate "Examples of Invalid Invoices" heading');

    const valid = collect(lines.slice(0, splitAt));
    const invalid = collect(lines.slice(splitAt));

    if (!valid.length || !invalid.length) {
        throw new Error(`extraction looks wrong: ${valid.length} valid, ${invalid.length} invalid`);
    }

    const header =
        `// GENERATED FILE - do not edit by hand.\n` +
        `//\n` +
        `// BOLT 11 test vectors extracted from the spec.\n` +
        `// Source: ${source}\n` +
        `// Regenerate: node test/extract-vectors.js [path-to-11-payment-encoding.md]\n` +
        `//\n` +
        `// VALID_VECTORS   - a conforming reader MUST decode these.\n` +
        `// INVALID_VECTORS - a conforming reader MUST reject these.\n\n`;

    fs.writeFileSync(OUT,
        header +
        serialize('VALID_VECTORS', valid) + '\n' +
        serialize('INVALID_VECTORS', invalid) + '\n' +
        `module.exports = { VALID_VECTORS, INVALID_VECTORS };\n`
    );

    console.log(`wrote ${path.relative(process.cwd(), OUT)}: ${valid.length} valid, ${invalid.length} invalid`);
})();
