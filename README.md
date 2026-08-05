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

**[BOLT 12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)** — all three
forms the spec defines.

*Offers* (`lno`) — all eleven offer TLV fields, including blinded paths, currency-denominated
amounts, feature bits and quantity limits. Offers carry no checksum and no signature, both by
design.

```
lno1pqpzwyq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj
```

*Invoice requests* (`lnr`) — the offer fields a request copies plus types 0 and 80 through 91,
with the BIP-340 Schnorr signature verified against `invreq_payer_id` over the merkle root.

*Payer proofs* (`lnp`) — a proof discloses a chosen subset of an invoice. The invoice's merkle
root is rebuilt from the disclosed fields, the supplied nonce hashes and the hashes standing in
for omitted subtrees, then two signatures are checked: `signature` against `invoice_node_id`
and `proof_signature` against `invreq_payer_id`. The payment preimage is checked against the
payment hash. Withheld fields are reported as withheld — how many, though not which, since the
format hides their identities deliberately.

Each decode shows three sections: the human-readable fields, a breakdown of the raw request,
and the decoded JSON.

## Not supported

BOLT 12 defines human-readable prefixes for those three forms only. Invoices normally travel
over onion messages rather than as strings, and the spec defines no prefix for them — though
its own payer proof test vectors serialise invoices as `lni1…`, as some implementations do.

Rules that need state a string decoder does not have are not enforced: whether an invoice
request matches a real unexpired offer, whether a chain is one the reader supports, whether
`invreq_metadata` repeats an earlier request, and how a request arrived. An offer amount
denominated in a currency is shown in that currency's ISO 4217 minor units rather than
converted, and is not compared against a requested millisatoshi amount.

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
