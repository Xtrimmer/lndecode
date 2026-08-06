const js = require('@eslint/js');

// The browser sources load as separate script tags sharing one global scope, so a name
// defined in one file is visible in the others. These are the names that actually cross a
// file boundary; anything else is file-local.
const SHARED = [
    'bech32CharValues', 'bech32ToFiveBitArray', 'bolt12ToBytes', 'branchNode',
    'byteArrayToHexString', 'byteReader', 'bytesToUtf8String', 'decode', 'decodeChains',
    'decodeInvoiceRequest', 'decodeOffer', 'decodePaths', 'decodePayerProof',
    'decodePointField', 'decodeRequest', 'decodeTruncatedUint', 'epochToDate', 'expand',
    'fallbackAddress', 'fiveBitArrayTo8BitArray', 'fiveBitArrayToBytes',
    'hexStringToByteArray', 'isBech32Character', 'isEmptyOrSpaces', 'isSignatureType',
    'jsonReplacer', 'leafHash', 'merkleRoot', 'parseTlvStream', 'polymod', 'readPrefix',
    'reconstructRoot', 'requireBech32Characters', 'requireConsistentCase',
    'requireUnderstoodTypes', 'sha256', 'signatureHash', 'signedRecords', 'subRows',
    'textToByteArray', 'textToHexString', 'toFixed', 'verifyBolt12Signature',
    'verifySignedStream'
];

const BROWSER = ['console', 'document', 'window', 'crypto', 'TextEncoder', 'TextDecoder'];

function readonlyGlobals(names) {
    return Object.fromEntries(names.map(name => [name, 'readonly']));
}

const STYLE = {
    'prefer-const': 'error',
    'no-var': 'error',
    eqeqeq: ['error', 'always'],
    'prefer-template': 'error',
    'object-shorthand': ['error', 'properties'],
    'no-else-return': 'error',
    'prefer-arrow-callback': 'error',
    'no-useless-concat': 'error',
    'dot-notation': 'error',
    'no-lonely-if': 'error',
    yoda: 'error'
};

module.exports = [
    {
        ignores: ['js/vendor/**', 'node_modules/**', 'test/vectors.js']
    },
    {
        linterOptions: {
            // A disable comment that stops being needed is itself an error.
            reportUnusedDisableDirectives: 'error'
        }
    },
    js.configs.recommended,
    {
        // The page sources: plain scripts, no module system.
        files: ['js/**/*.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'script',
            globals: {
                ...readonlyGlobals(BROWSER),
                ...readonlyGlobals(SHARED),
                secp256k1: 'readonly',
                globalThis: 'readonly'
            }
        },
        rules: {
            ...STYLE,
            // A name declared here is also listed as a shared global above.
            'no-redeclare': 'off',
            // Top-level names are the cross-file interface, so only function-local
            // bindings are checked. test/dead-code.test.js covers the top level, where it
            // can see the other files, index.html and the tests.
            'no-unused-vars': ['error', { vars: 'local', args: 'after-used', caughtErrors: 'all' }]
        }
    },
    {
        // Tests and tooling: CommonJS on Node.
        files: ['test/**/*.js', 'tools/**/*.js', 'eslint.config.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'commonjs',
            globals: {
                ...readonlyGlobals(['console', 'process', 'require', 'module', 'exports',
                    '__dirname', '__filename', 'Buffer', 'fetch', 'globalThis'])
            }
        },
        rules: STYLE
    }
];
