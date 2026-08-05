// Loads the browser sources into a sandbox for testing under Node. render.js is omitted.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SOURCES = ['utils.js', 'bech32.js', 'bytes.js', 'sha256.js', 'merkle.js',
    'vendor/secp256k1.js', 'bolt12sig.js', 'address.js', 'bolt11.js', 'bolt12.js',
    'bolt12proof.js', 'bolt12invreq.js', 'dispatch.js'];

function load() {
    const dir = path.join(__dirname, '..', 'js');
    const code = SOURCES
        .map(file => `//--- ${file} ---\n${fs.readFileSync(path.join(dir, file), 'utf8')}`)
        .join('\n');

    const sandbox = { console };
    vm.createContext(sandbox);
    vm.runInContext(code, sandbox, { filename: 'lndecode.bundle.js' });
    return sandbox;
}

module.exports = { load, SOURCES };
