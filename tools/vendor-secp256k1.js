// Vendors @noble/secp256k1 as a classic script.
//
//   npm run vendor
//
// Upstream is a single file with no imports. Two transformations make it loadable with a
// plain script tag: the two export statements are removed, and a shim assigning the
// public names to globalThis.secp256k1 is appended. The library body is unchanged.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const VERSION = '3.1.0';
const SOURCE = `https://cdn.jsdelivr.net/npm/@noble/secp256k1@${VERSION}/index.js`;
const OUT = path.join(__dirname, '..', 'js', 'vendor', 'secp256k1.js');

const SHIM = `
globalThis.secp256k1 = {
    Point, Signature, verify, recoverPublicKey, schnorr, hashes, etc, utils
};
`;

(async () => {
    const res = await fetch(SOURCE);
    if (!res.ok) throw new Error(`fetch failed: ${res.status} ${res.statusText}`);
    const upstream = await res.text();

    const digest = crypto.createHash('sha256').update(upstream).digest('hex');

    if (/^\s*import\s/m.test(upstream)) {
        throw new Error('upstream now has import statements; the classic-script transform no longer applies');
    }
    const exportCount = (upstream.match(/^export /gm) || []).length;
    if (exportCount !== 2) {
        throw new Error(`expected 2 export statements upstream, found ${exportCount}`);
    }

    let body = upstream
        .replace(/^export const /gm, 'const ')
        .replace(/^export \{[^}]*\};\s*$/gm, '');

    if (/^export /m.test(body)) throw new Error('an export statement survived the transform');

    const header =
        `// @noble/secp256k1 ${VERSION} -- MIT, (c) Paul Miller\n` +
        `// Source: ${SOURCE}\n` +
        `// sha256 of upstream: ${digest}\n` +
        `// Vendored by tools/vendor-secp256k1.js: export statements removed, global shim appended.\n` +
        `// Regenerate: npm run vendor\n\n`;

    fs.writeFileSync(OUT, header + body + SHIM);
    console.log(`  wrote js/vendor/secp256k1.js (${(header + body + SHIM).length} bytes)`);
    console.log(`  upstream sha256 ${digest}`);
})();
