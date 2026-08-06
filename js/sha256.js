// SHA-256 over a byte array, per FIPS 180-4.

const SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

const SHA256_INITIAL = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

function rotateRight32(value, bits) {
    return ((value >>> bits) | (value << (32 - bits))) >>> 0;
}

// Appends the 0x80 marker, zero padding, and the 64-bit big-endian bit length.
function sha256Pad(bytes) {
    const padded = Array.prototype.slice.call(bytes);
    padded.push(0x80);
    while (padded.length % 64 !== 56) {
        padded.push(0);
    }
    const high = Math.floor(bytes.length / 536870912);
    const low = (bytes.length * 8) >>> 0;
    padded.push((high >>> 24) & 255, (high >>> 16) & 255, (high >>> 8) & 255, high & 255);
    padded.push((low >>> 24) & 255, (low >>> 16) & 255, (low >>> 8) & 255, low & 255);
    return padded;
}

// Returns the digest as an array of 32 bytes.
function sha256(bytes) {
    let hash = SHA256_INITIAL.slice();
    const padded = sha256Pad(bytes);
    const w = new Array(64);

    for (let block = 0; block < padded.length; block += 64) {
        for (let i = 0; i < 16; i++) {
            const at = block + i * 4;
            w[i] = ((padded[at] << 24) | (padded[at + 1] << 16) | (padded[at + 2] << 8) | padded[at + 3]) >>> 0;
        }
        for (let i = 16; i < 64; i++) {
            const s0 = rotateRight32(w[i - 15], 7) ^ rotateRight32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            const s1 = rotateRight32(w[i - 2], 17) ^ rotateRight32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
        }

        let a = hash[0], b = hash[1], c = hash[2], d = hash[3];
        let e = hash[4], f = hash[5], g = hash[6], h = hash[7];

        for (let i = 0; i < 64; i++) {
            const sigma1 = rotateRight32(e, 6) ^ rotateRight32(e, 11) ^ rotateRight32(e, 25);
            const choose = (e & f) ^ (~e & g);
            const t1 = (h + sigma1 + choose + SHA256_K[i] + w[i]) >>> 0;
            const sigma0 = rotateRight32(a, 2) ^ rotateRight32(a, 13) ^ rotateRight32(a, 22);
            const majority = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (sigma0 + majority) >>> 0;

            h = g;
            g = f;
            f = e;
            e = (d + t1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (t1 + t2) >>> 0;
        }

        hash = [
            (hash[0] + a) >>> 0, (hash[1] + b) >>> 0, (hash[2] + c) >>> 0, (hash[3] + d) >>> 0,
            (hash[4] + e) >>> 0, (hash[5] + f) >>> 0, (hash[6] + g) >>> 0, (hash[7] + h) >>> 0
        ];
    }

    const digest = [];
    for (const word of hash) {
        digest.push((word >>> 24) & 255, (word >>> 16) & 255, (word >>> 8) & 255, word & 255);
    }
    return digest;
}
