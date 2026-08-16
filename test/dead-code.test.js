// Every top-level name in public/js/ lands on the global object, so eslint cannot tell an
// unused one from the cross-file interface. This checks the whole project at once: a name
// must be used by another source file, by index.html, or by a test.

const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { SOURCES } = require('./load.js');

const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const JS_DIR = path.join(PUBLIC_DIR, 'js');

const SOURCE_FILES = fs.readdirSync(JS_DIR)
    .filter(name => name.endsWith('.js'))
    .sort();

const TEST_FILES = fs.readdirSync(__dirname)
    .filter(name => name.endsWith('.js'))
    .map(name => path.join(__dirname, name));

function read(file) {
    return fs.readFileSync(file, 'utf8');
}

function topLevelNames(source) {
    return Array.from(source.matchAll(/^(?:const|let|var|function|class)\s+([A-Za-z_$][\w$]*)/gm),
        match => match[1]);
}

// A bare word, not a property access.
function references(source, name) {
    return new RegExp(`(^|[^.\\w$])${name}(?![\\w$])`).test(source);
}

function propertyReferences(source, name) {
    return new RegExp(`\\.${name}(?![\\w$])`).test(source);
}

const OTHER_SOURCES = new Map(SOURCE_FILES
    .filter(name => name !== 'vendor')
    .map(name => [name, read(path.join(JS_DIR, name))]));

describe('the source list', () => {
    test('load.js covers every file index.html loads', () => {
        const html = read(path.join(PUBLIC_DIR, 'index.html'));
        const loaded = Array.from(html.matchAll(/<script src="js\/([^"]+)"><\/script>/g),
            match => match[1]);
        // render.js touches the DOM, so the test loader omits it.
        assert.deepStrictEqual(SOURCES, loaded.filter(name => name !== 'render.js'));
    });

    test('every file in public/js/ is loaded by the page', () => {
        const html = read(path.join(PUBLIC_DIR, 'index.html'));
        for (const name of SOURCE_FILES) {
            if (name === 'vendor') continue;
            assert.ok(html.includes(`js/${name}`), `${name} is not loaded by index.html`);
        }
    });
});

describe('no dead top-level code', () => {
    const html = read(path.join(PUBLIC_DIR, 'index.html'));
    const testSource = TEST_FILES.map(read).join('\n');

    for (const [file, source] of OTHER_SOURCES) {
        test(`every name ${file} defines is used somewhere`, () => {
            const unused = [];
            for (const name of topLevelNames(source)) {
                const usedHere = references(source.replace(
                    new RegExp(`^(?:const|let|var|function|class)\\s+${name}\\b`, 'gm'), ''), name);
                const usedElsewhere = Array.from(OTHER_SOURCES)
                    .some(([other, text]) => other !== file && references(text, name));
                const usedByPage = references(html, name);
                const usedByTests = references(testSource, name)
                    || propertyReferences(testSource, name);
                if (!usedHere && !usedElsewhere && !usedByPage && !usedByTests) unused.push(name);
            }
            assert.deepStrictEqual(unused, [], `unused in ${file}`);
        });
    }
});

describe('the shared global surface', () => {
    // Two files declaring the same top-level name is a SyntaxError when the page loads
    // them as separate scripts, which no test would otherwise reach.
    test('no name is declared by two source files', () => {
        const owners = new Map();
        const clashes = [];
        for (const [file, source] of OTHER_SOURCES) {
            for (const name of topLevelNames(source)) {
                if (owners.has(name)) clashes.push(`${name}: ${owners.get(name)} and ${file}`);
                else owners.set(name, file);
            }
        }
        assert.deepStrictEqual(clashes, []);
    });

    test('the vendored library does not clash with a source name', () => {
        const vendor = read(path.join(JS_DIR, 'vendor', 'secp256k1.js'));
        const vendorNames = new Set(topLevelNames(vendor));
        const clashes = [];
        for (const [file, source] of OTHER_SOURCES) {
            for (const name of topLevelNames(source)) {
                if (vendorNames.has(name)) clashes.push(`${name} in ${file}`);
            }
        }
        assert.deepStrictEqual(clashes, []);
    });

    test('eslint.config.js lists the names that cross a file boundary', () => {
        const config = read(path.join(ROOT, 'eslint.config.js'));
        const declared = new Set(Array.from(
            config.slice(config.indexOf('const SHARED'), config.indexOf('const BROWSER'))
                .matchAll(/'([A-Za-z_$][\w$]*)'/g), match => match[1]));

        const missing = [];
        for (const [file, source] of OTHER_SOURCES) {
            for (const name of topLevelNames(source)) {
                const crosses = Array.from(OTHER_SOURCES)
                    .some(([other, text]) => other !== file && references(text, name));
                if (crosses && !declared.has(name)) missing.push(`${name} (${file})`);
            }
        }
        assert.deepStrictEqual(missing, [],
            'add these to SHARED in eslint.config.js so no-undef stays accurate');
    });
});
