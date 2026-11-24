// AES-128 (sens unique : GCM ne vit que du compteur) et GCM avec un
// GHASH bit a bit — lent et simple, le testeur veut dire correct avant
// rapide. La S-box est calculee (inverse dans GF(2^8) + affine), pas
// recopiee de memoire.
namespace net;
import std;

const SBOX: u8[256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// l'expansion de cle : 11 cles de tour de 16 octets
struct Aes128 { rk: u8[176] = [0; 176] }

fn aes128_init(key: const u8[:]) -> Aes128 {
    var a = Aes128 { .. };
    a.rk[..16].move_from(key[..16]);
    let rcon: u8[10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    for i in 4..44 {
        var t: u8[4] = [0; 4];
        t[0] = a.rk[4 * i - 4];
        t[1] = a.rk[4 * i - 3];
        t[2] = a.rk[4 * i - 2];
        t[3] = a.rk[4 * i - 1];
        if i % 4 == 0 {
            // RotWord puis SubWord puis Rcon
            let f = t[0];
            t[0] = SBOX[t[1]];
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[f];
            t[0] ^= rcon[i / 4 - 1];
        }
        for j in 4 {
            a.rk[4 * i + j] = a.rk[4 * i - 16 + j] ^ t[j];
        }
    }
    return a;
}

// un bloc de 16 octets, dans src, hors dst
fn aes128_block(a: Aes128&, src: const u8[:], dst: u8[:]) {
    var st: u8[16] = [0; 16];
    st[..].move_from(src[..16]);
    add_round_key(st, a.rk[..], 0);
    for r in 1..10 {
        for i in 16 { st[i] = SBOX[st[i]]; }
        shift_rows(st);
        mix_columns(st);
        add_round_key(st, a.rk[..], r);
    }
    for i in 16 { st[i] = SBOX[st[i]]; }
    shift_rows(st);
    add_round_key(st, a.rk[..], 10);
    dst[..16].move_from(st[..]);
}

// la ligne r tourne de r vers la gauche : (r, c) vit a r + 4c
fn shift_rows(st: u8[:]) {
    var t: u8[16] = [0; 16];
    t[..].move_from(st[..]);
    for r in 1..4 {
        for c in 4 {
            st[r + 4 * c] = t[r + 4 * ((c + r) % 4)];
        }
    }
}

fn add_round_key(st: u8[:], rk: u8[:], r: i64) {
    for i in 16 { st[i] ^= rk[16 * r + i]; }
}

fn xtime(v: u8) -> u8 {
    let hi = v & 0x80;
    var r = v << 1;
    if hi != 0 { r ^= 0x1b; }
    return r;
}

fn mix_columns(st: u8[:]) {
    for c in 4 {
        let a0 = st[4 * c];
        let a1 = st[4 * c + 1];
        let a2 = st[4 * c + 2];
        let a3 = st[4 * c + 3];
        st[4 * c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        st[4 * c + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        st[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        st[4 * c + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

// ---- GCM (NIST SP 800-38D) ----

// le produit dans GF(2^128), R = 0xe1 suivi de zeros
fn gfmul128(x: const u8[:], y: const u8[:]) -> u8[16] {
    var z: u8[16] = [0; 16];
    var v: u8[16] = [0; 16];
    v[..].move_from(x[..16]);
    for i in 128 {
        // le bit i de y, du plus significatif au moins
        let byte = y[i / 8];
        if (byte >> (7 - i % 8)) & 1 == 1 {
            for j in 16 { z[j] ^= v[j]; }
        }
        // v = v >> 1, avec le bit de poids faible qui revient comme R
        let lsb = v[15] & 1;
        shift_right1(v);
        if lsb == 1 { v[0] ^= 0xe1; }
    }
    return z;
}

fn shift_right1(v: u8[:]) {
    var carry: u8 = 0;
    for i in 16 {
        let nc = v[i] & 1;
        v[i] = (v[i] >> 1) | carry;
        carry = if nc == 1 { 0x80 } else { 0 };
    }
}

// inc32 : les quatre derniers octets du bloc compteur, gros-boutiste
fn inc32(blk: u8[:]) {
    var c: u32 = ((blk[12] as u32) << 24) | ((blk[13] as u32) << 16) | ((blk[14] as u32) << 8) | blk[15];
    c++;
    blk[12] = (c >> 24) as u8;
    blk[13] = (c >> 16) as u8;
    blk[14] = (c >> 8) as u8;
    blk[15] = c as u8;
}

// GHASH : Y ^= bloc, puis Y = produit(Y, H), sur aad puis donnees
// completees de zeros, fermees par les longueurs en bits
fn ghash(h: const u8[:], aad: const u8[:], data: const u8[:]) -> u8[16] {
    var y: u8[16] = [0; 16];
    var at = 0;
    while at < aad.len {
        let n = min(16, aad.len - at);
        for i in n { y[i] ^= aad[at + i]; }
        y = gfmul128(y, h);
        at += 16;
    }
    at = 0;
    while at < data.len {
        let n = min(16, data.len - at);
        for i in n { y[i] ^= data[at + i]; }
        y = gfmul128(y, h);
        at += 16;
    }
    var lens: u8[16] = [0; 16];
    let abits = aad.len * 8;
    let dbits = data.len * 8;
    for i in 8 { lens[i] = (abits >> (56 - 8 * i)) as u8; }
    for i in 8 { lens[8 + i] = (dbits >> (56 - 8 * i)) as u8; }
    for i in 16 { y[i] ^= lens[i]; }
    return gfmul128(y, h);
}

// chiffre ou dechiffre en CTR depuis j0, compteur a partir de 1 ; le
// meme appel sert aux deux sens, le XOR est son propre inverse
fn gcm128_ctr(a: Aes128&, j0: const u8[:], data: const u8[:], out: u8[>..]&) {
    var ctr: u8[16] = [0; 16];
    ctr[..].move_from(j0[..16]);
    var at = 0;
    while at < data.len {
        inc32(ctr);
        var ks: u8[16] = [0; 16];
        aes128_block(a, ctr, ks);
        let n = min(16, data.len - at);
        for i in n { out.push(data[at + i] ^ ks[i]); }
        at += 16;
    }
}

// scelle : rend le tag ; le chiffre atterrit dans out
fn gcm128_seal(key: const u8[:], iv: const u8[:], aad: const u8[:], pt: const u8[:], out: u8[>..]&) -> u8[16] {
    var a = aes128_init(key);
    var j0: u8[16] = [0; 16];
    j0[..12].move_from(iv[..12]);
    j0[15] = 1;
    var h:    u8[16] = [0; 16];
    var zero: u8[16] = [0; 16];
    aes128_block(a, zero, h);
    out.clear();
    gcm128_ctr(a, j0, pt, out);
    let gy = ghash(h, aad, out[..]);
    var tag: u8[16] = [0; 16];
    var ek0: u8[16] = [0; 16];
    aes128_block(a, j0, ek0);
    for i in 16 { tag[i] = ek0[i] ^ gy[i]; }
    return tag;
}

// ouvre : verifie le tag avant de livrer quoi que ce soit d utile ;
// false et un out vide si le tag ne colle pas
fn gcm128_open(key: const u8[:], iv: const u8[:], aad: const u8[:], ct: const u8[:], tag: const u8[:], out: u8[>..]&) -> bool {
    var a = aes128_init(key);
    var j0: u8[16] = [0; 16];
    j0[..12].move_from(iv[..12]);
    j0[15] = 1;
    var h:    u8[16] = [0; 16];
    var zero: u8[16] = [0; 16];
    aes128_block(a, zero, h);
    let gy = ghash(h, aad, ct);
    var ek0: u8[16] = [0; 16];
    aes128_block(a, j0, ek0);
    var diff: u8 = 0;
    for i in 16 { diff |= ek0[i] ^ gy[i] ^ tag[i]; }
    if diff != 0 { out.clear(); return false; }
    gcm128_ctr(a, j0, ct, out);
    return true;
}
