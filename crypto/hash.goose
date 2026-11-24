// SHA-256 et SHA-512 (donc 384) en version streaming — le transcript TLS
// hash au fil des messages, un état par connexion — puis HMAC et HKDF
// par-dessus. Les constantes sont les fractions des racines carrées
// (IV) et cubiques (K) des premiers nombres premiers ; les vecteurs de
// test sont dans test/vectors.goose.
namespace net;
import std;

const K256: u32[64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 { h: u8[32] = [0; 32], buf: u8[64] = [0; 64], fill: i32 = 0, total: i64 = 0 }

fn sha256_init() -> Sha256 {
    var s = Sha256 { .. };
    be_put32(s.h[..], 0, 0x6a09e667);
    be_put32(s.h[..], 4, 0xbb67ae85);
    be_put32(s.h[..], 8, 0x3c6ef372);
    be_put32(s.h[..], 12, 0xa54ff53a);
    be_put32(s.h[..], 16, 0x510e527f);
    be_put32(s.h[..], 20, 0x9b05688c);
    be_put32(s.h[..], 24, 0x1f83d9ab);
    be_put32(s.h[..], 28, 0x5be0cd19);
    return s;
}

fn sha256_update(s: Sha256&, data: const u8[:]) {
    s.total += data.len;
    var at = 0;
    if s.fill > 0 && s.fill < 64 {
        let want = min((64 - s.fill) as i64, data.len);
        s.buf[s.fill..s.fill + want].move_from(data[..want]);
        s.fill += want as i32;
        at = want;
        if s.fill < 64 { return; }
        sha256_block_buf(s, s.buf[..]);
        s.fill = 0;
    }
    while data.len - at >= 64 {
        sha256_block_buf(s, data[at..at + 64]);
        at += 64;
    }
    if at < data.len {
        let left = data.len - at;
        s.buf[..left].move_from(data[at..]);
        s.fill = left as i32;
    }
}

// le bourrage et la longueur, puis le débit final
fn sha256_final(s: Sha256&, out: u8[32]&) {
    let bits = s.total * 8;
    var at = s.fill;
    s.buf[at] = 0x80;
    at++;
    if at > 56 {
        for i in at..64 { s.buf[i] = 0; }
        sha256_block_buf(s, s.buf[..]);
        at = 0;
    }
    for i in at..56 { s.buf[i] = 0; }
    for i in 8 {
        s.buf[56 + i] = (bits >> (56 - 8 * i)) as u8;
    }
    sha256_block_buf(s, s.buf[..]);
    out[..].move_from(s.h[..]);
}

fn sha256(data: const u8[:]) -> u8[32] {
    var s = sha256_init();
    sha256_update(s, data);
    var out: u8[32] = [0; 32];
    sha256_final(s, out);
    return out;
}

fn sha256_block_buf(s: Sha256&, blk: const u8[:]) {
    var w: u32[64] = [0; 64];
    for i in 16 {
        w[i] = be_get32(blk, i * 4);
    }
    for i in 16..64 {
        let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    var a = be_get32(s.h[..], 0);
    var b = be_get32(s.h[..], 4);
    var c = be_get32(s.h[..], 8);
    var d = be_get32(s.h[..], 12);
    var e = be_get32(s.h[..], 16);
    var f = be_get32(s.h[..], 20);
    var g = be_get32(s.h[..], 24);
    var h = be_get32(s.h[..], 28);
    for i in 64 {
        let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        let ch = (e & f) ^ (~e & g);
        let t1 = h + s1 + ch + K256[i] + w[i];
        let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    be_put32(s.h[..], 0, be_get32(s.h[..], 0) + a);
    be_put32(s.h[..], 4, be_get32(s.h[..], 4) + b);
    be_put32(s.h[..], 8, be_get32(s.h[..], 8) + c);
    be_put32(s.h[..], 12, be_get32(s.h[..], 12) + d);
    be_put32(s.h[..], 16, be_get32(s.h[..], 16) + e);
    be_put32(s.h[..], 20, be_get32(s.h[..], 20) + f);
    be_put32(s.h[..], 24, be_get32(s.h[..], 24) + g);
    be_put32(s.h[..], 28, be_get32(s.h[..], 28) + h);
}

// SHA-512 et SHA-384 : les mêmes mécanismes sur des mots de 64 bits.
const K512: u64[80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0xfc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x6ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x6f067aa72176fba, 0xa637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

struct Sha512 { h: u8[64] = [0; 64], buf: u8[128] = [0; 128], fill: i32 = 0, total: i64 = 0 }

fn sha512_init() -> Sha512 {
    var s = Sha512 { .. };
    be_put64(s.h[..], 0, 0x6a09e667f3bcc908);
    be_put64(s.h[..], 8, 0xbb67ae8584caa73b);
    be_put64(s.h[..], 16, 0x3c6ef372fe94f82b);
    be_put64(s.h[..], 24, 0xa54ff53a5f1d36f1);
    be_put64(s.h[..], 32, 0x510e527fade682d1);
    be_put64(s.h[..], 40, 0x9b05688c2b3e6c1f);
    be_put64(s.h[..], 48, 0x1f83d9abfb41bd6b);
    be_put64(s.h[..], 56, 0x5be0cd19137e2179);
    return s;
}

fn sha384_init() -> Sha512 {
    var s = Sha512 { .. };
    be_put64(s.h[..], 0, 0xcbbb9d5dc1059ed8);
    be_put64(s.h[..], 8, 0x629a292a367cd507);
    be_put64(s.h[..], 16, 0x9159015a3070dd17);
    be_put64(s.h[..], 24, 0x152fecd8f70e5939);
    be_put64(s.h[..], 32, 0x67332667ffc00b31);
    be_put64(s.h[..], 40, 0x8eb44a8768581511);
    be_put64(s.h[..], 48, 0xdb0c2e0d64f98fa7);
    be_put64(s.h[..], 56, 0x47b5481dbefa4fa4);
    return s;
}

fn sha512_update(s: Sha512&, data: const u8[:]) {
    s.total += data.len;
    var at = 0;
    if s.fill > 0 && s.fill < 128 {
        let want = min((128 - s.fill) as i64, data.len);
        s.buf[s.fill..s.fill + want].move_from(data[..want]);
        s.fill += want as i32;
        at = want;
        if s.fill < 128 { return; }
        sha512_block(s, s.buf[..]);
        s.fill = 0;
    }
    while data.len - at >= 128 {
        sha512_block(s, data[at..at + 128]);
        at += 128;
    }
    if at < data.len {
        let left = data.len - at;
        s.buf[..left].move_from(data[at..]);
        s.fill = left as i32;
    }
}

fn sha512_final(s: Sha512&, out: u8[64]&) {
    let bits = s.total * 8;
    var at = s.fill;
    s.buf[at] = 0x80;
    at++;
    if at > 112 {
        for i in at..128 { s.buf[i] = 0; }
        sha512_block(s, s.buf[..]);
        at = 0;
    }
    for i in at..112 { s.buf[i] = 0; }
    // la longueur sur 128 bits : les huit premiers octets sont toujours
    // nuls chez nous (total est un i64), et le decalage des huit suivants
    // reste dans la largeur du mot - un compte de 120 serait masque a 56
    for i in 8 { s.buf[112 + i] = 0; }
    for i in 8 {
        s.buf[120 + i] = (bits >> (56 - 8 * i)) as u8;
    }
    sha512_block(s, s.buf[..]);
    out[..].move_from(s.h[..]);
}

fn sha384_final(s: Sha512&, out: u8[48]&) {
    var full: u8[64] = [0; 64];
    sha512_final(s, full);
    out[..].move_from(full[..48]);
}

fn sha384(data: const u8[:]) -> u8[48] {
    var s = sha384_init();
    sha512_update(s, data);
    var out: u8[48] = [0; 48];
    sha384_final(s, out);
    return out;
}

fn sha512(data: const u8[:]) -> u8[64] {
    var s = sha512_init();
    sha512_update(s, data);
    var out: u8[64] = [0; 64];
    sha512_final(s, out);
    return out;
}

fn sha512_block(s: Sha512&, blk: const u8[:]) {
    var w: u64[80] = [0; 80];
    for i in 16 {
        w[i] = be_get64(blk, i * 8);
    }
    for i in 16..80 {
        let s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        let s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    var a = be_get64(s.h[..], 0);
    var b = be_get64(s.h[..], 8);
    var c = be_get64(s.h[..], 16);
    var d = be_get64(s.h[..], 24);
    var e = be_get64(s.h[..], 32);
    var f = be_get64(s.h[..], 40);
    var g = be_get64(s.h[..], 48);
    var h = be_get64(s.h[..], 56);
    for i in 80 {
        let s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        let ch = (e & f) ^ (~e & g);
        let t1 = h + s1 + ch + K512[i] + w[i];
        let s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    be_put64(s.h[..], 0, be_get64(s.h[..], 0) + a);
    be_put64(s.h[..], 8, be_get64(s.h[..], 8) + b);
    be_put64(s.h[..], 16, be_get64(s.h[..], 16) + c);
    be_put64(s.h[..], 24, be_get64(s.h[..], 24) + d);
    be_put64(s.h[..], 32, be_get64(s.h[..], 32) + e);
    be_put64(s.h[..], 40, be_get64(s.h[..], 40) + f);
    be_put64(s.h[..], 48, be_get64(s.h[..], 48) + g);
    be_put64(s.h[..], 56, be_get64(s.h[..], 56) + h);
}

// Les rotations : Goose shifts at the operand's own width, donc le garde
// du zéro évite le compte nul qui ne tourne pas.
fn rotr32(x: u32, k: i64) -> u32 {
    if k == 0 { return x; }
    (x >> k) | (x << (32 - k))
}

fn rotr64(x: u64, k: i64) -> u64 {
    if k == 0 { return x; }
    (x >> k) | (x << (64 - k))
}

// gros-boutiste, pour tout ce que les specs nomment en octets
fn be_put32(out: u8[:], at: i64, v: u32) {
    out[at] = (v >> 24) as u8;
    out[at + 1] = (v >> 16) as u8;
    out[at + 2] = (v >> 8) as u8;
    out[at + 3] = v as u8;
}

fn be_get32(src: const u8[:], at: i64) -> u32 {
    (src[at] as u32 << 24) | (src[at + 1] as u32 << 16) | (src[at + 2] as u32 << 8) | src[at + 3]
}

fn be_put64(out: u8[:], at: i64, v: u64) {
    for i in 8 {
        out[at + i] = (v >> (56 - 8 * i)) as u8;
    }
}

fn be_get64(src: const u8[:], at: i64) -> u64 {
    var v: u64 = 0;
    for i in 8 {
        v = (v << 8) | src[at + i];
    }
    return v;
}

// HMAC-SHA256, avec les états ipad/opad pré-digestés : la clé est digérée
// une fois, chaque message ne coûte que deux compressions de plus.
struct Hmac256 { inner: Sha256, outer: Sha256 }

fn hmac256_init(key: const u8[:]) -> Hmac256 {
    var k: u8[64] = [0; 64];
    if key.len > 64 {
        var mid = sha256(key);
        k[..32].move_from(mid[..]);
    } else {
        k[..key.len].move_from(key);
    }
    var h = Hmac256 { inner: sha256_init(), outer: sha256_init() };
    var pads: u8[64] = [0; 64];
    for i in 64 { pads[i] = k[i] ^ 0x36; }
    sha256_update(h.inner, pads);
    for i in 64 { pads[i] = k[i] ^ 0x5c; }
    sha256_update(h.outer, pads);
    return h;
}

fn hmac256_update(h: Hmac256&, data: const u8[:]) {
    sha256_update(h.inner, data);
}

fn hmac256_final(h: Hmac256&) -> u8[32] {
    var mid: u8[32] = [0; 32];
    sha256_final(h.inner, mid);
    sha256_update(h.outer, mid);
    var out: u8[32] = [0; 32];
    sha256_final(h.outer, out);
    return out;
}

fn hmac256(key: const u8[:], data: const u8[:]) -> u8[32] {
    var h = hmac256_init(key);
    hmac256_update(h, data);
    return hmac256_final(h);
}

struct Hmac384 { inner: Sha512, outer: Sha512 }

fn hmac384_init(key: const u8[:]) -> Hmac384 {
    var k: u8[128] = [0; 128];
    if key.len > 128 {
        var mid = sha384(key);
        k[..48].move_from(mid[..]);
    } else {
        k[..key.len].move_from(key);
    }
    var h = Hmac384 { inner: sha384_init(), outer: sha384_init() };
    var pads: u8[128] = [0; 128];
    for i in 128 { pads[i] = k[i] ^ 0x36; }
    sha512_update(h.inner, pads);
    for i in 128 { pads[i] = k[i] ^ 0x5c; }
    sha512_update(h.outer, pads);
    return h;
}

fn hmac384_update(h: Hmac384&, data: const u8[:]) {
    sha512_update(h.inner, data);
}

fn hmac384_final(h: Hmac384&) -> u8[48] {
    var mid: u8[48] = [0; 48];
    sha384_final(h.inner, mid);
    sha512_update(h.outer, mid);
    var out: u8[48] = [0; 48];
    sha384_final(h.outer, out);
    return out;
}

// RFC 5869 : extract = HMAC(salt, ikm).
fn hkdf_extract256(salt: const u8[:], ikm: const u8[:]) -> u8[32] {
    return hmac256(salt, ikm);
}

// RFC 5869 : expand = les blocs T(i) = HMAC(prk, T(i-1) || info || i),
// écrits dans out jusqu'à couvrir len octets.
fn hkdf_expand256(prk: const u8[:], info: const u8[:], len: i64, out: u8[>..]&) {
    out.clear();
    var t:       u8[32] = [0; 32];
    var counter: u8     = 1;
    while out.len < len {
        var h = hmac256_init(prk);
        if out.len > 0 { hmac256_update(h, t); }
        hmac256_update(h, info);
        var cb: u8[1] = [counter; 1];
        hmac256_update(h, cb[..]);
        t = hmac256_final(h);
        let want = min(len - out.len, 32);
        out.append(t[..want]);
        counter++;
    }
}

// l'habillage TLS 1.3 : "tls13 " + label. Le HkdfLabel du RFC 8446 7.1
// met la longueur finale sur 16 bits, puis l'etiquette et le contexte,
// chacun prefixe d'un SEUL octet — des vecteurs <7..255>, pas des u16
fn hkdf_expand_label256(prk: const u8[:], label: const u8[:], context: const u8[:], len: i64, out: u8[>..]&) {
    var info: u8[>..] = [];
    put_u16be(info, len as u16);
    info.push((6 + label.len) as u8);
    info.append("tls13 ");
    info.append(label);
    info.push(context.len as u8);
    info.append(context);
    hkdf_expand256(prk, info[..], len, out);
}

// derive-secret : expand-label sur le hash du transcript
fn derive_secret256(prk: const u8[:], label: const u8[:], transcript: const u8[:], out: u8[32]&) {
    var th = sha256(transcript);
    var d: u8[>..] = [];
    hkdf_expand_label256(prk, label, th[..], 32, d);
    out[..].move_from(d[..32]);
}

fn put_u16be(out: u8[>..]&, v: u16) {
    out.push((v >> 8) as u8);
    out.push(v as u8);
}
