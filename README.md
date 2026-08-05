# lndecoder

Decodes Lightning Network payment requests and offers in the browser. No build step, no
server, no dependencies at runtime — open `index.html` and it works, including over
`file://`.

Go to https://lndecode.com/ and paste a request string into the text box.

## What it decodes

**[BOLT 11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md) payment
requests** — `lnbc`, `lntb`, `lntbs`, `lnbcrt`, `lnsb`.

All ten tagged fields (`p` `s` `d` `m` `n` `h` `x` `c` `f` `r`), bech32 checksum
verification, ECDSA signature verification with public key recovery, multi-hop routing
hints, and fallback addresses in all five forms (P2PKH, P2SH, P2WPKH, P2WSH, P2TR).

```
lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh
```

**[BOLT 12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md) offers** —
`lno`.

All eleven offer TLV fields (types 2 through 22), including blinded paths, currency-denominated
amounts, feature bits, and quantity limits. Offers carry no checksum and no signature, both by
design.

```
lno1pqpzwyq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj
```

Each decode shows three sections: the human-readable fields, a character-by-character
breakdown of the raw request, and the decoded JSON.

## Not yet supported

BOLT 12 invoice requests (`lnr`) and payer proofs (`lnp`) are recognised and reported as
unsupported rather than mis-parsed. Both are signed forms, so they need the BIP-340 Schnorr
and merkle-root layer that isn't built yet.

BOLT 12 invoices have no bech32 prefix at all — they travel over onion messages — so there
is nothing for a string decoder to accept.

## URL parameter

Append the request string to the URL to decode it on load. The parameter is named `invoice`
for backwards compatibility, but it accepts offers too.

https://lndecode.com/?invoice=lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh

## Tests

```
npm test        # runs every suite against the published spec vectors
npm run vectors # re-extracts vectors from lightning/bolts; a clean diff means current
npm run vendor  # regenerates js/vendor/secp256k1.js from @noble/secp256k1
```

Test vectors are extracted from the [lightning/bolts](https://github.com/lightning/bolts)
repository rather than hand-written: 26 BOLT 11 invoices, 53 offers, 12 format strings, and
the BOLT 1 BigSize suite.
