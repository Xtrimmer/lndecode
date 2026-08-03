// Loads the browser sources into a sandbox so they can be tested under Node
// without adding module boilerplate to the files the page actually ships.
//
// js/pageupdate.js is deliberately excluded: it touches the DOM on load.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SOURCES = ['utils.js', 'decoder.js'];

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
