// P-256 (FIPS 186-4) pour l'ECDH du handshake et les signatures
// ecdsa_secp256r1_sha256. Les points vivent en coordonnees Jacobian sur
// le corps de Montgomery, l'inversion n'arrive qu'a la sortie ; le k de
// signature est deterministe (RFC 6979), donc nos signatures tombent
// octet pour octet comme celles d'OpenSSL.
namespace net;
import std;
import .big;
import .hash;

var P256_P  = big_from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
var P256_N  = big_from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
var P256_GX = big_from_hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
var P256_GY = big_from_hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
var P256_MP = mont_setup(P256_P);
var P256_MN = mont_setup(P256_N);
var P256_AM = mont_in(big_from_hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"), P256_MP);

// l'arithmetique du corps, entrees et sorties dans le domaine de Montgomery

fn p256_fm(a: Big, b: Big) -> Big {
    return mont_mul(a, b, P256_MP);
}

fn p256_fa(a: Big, b: Big) -> Big {
    var r = big_add(a, b);
    if big_cmp(r, P256_P) >= 0 { r = big_sub(r, P256_P); }
    return r;
}

fn p256_fs(a: Big, b: Big) -> Big {
    if big_cmp(a, b) < 0 {
        return big_sub(big_add(a, P256_P), b);
    }
    return big_sub(a, b);
}

// l'entre et la sortie du domaine, pour charger les constantes
fn p256_fin(x: Big) -> Big {
    return mont_in(x, P256_MP);
}

fn p256_fout(x: Big) -> Big {
    return mont_out(x, P256_MP);
}

// un point Jacobian : z de longueur nulle, c est l'infini
struct PtJ { x: Big = Big { .. }, y: Big = Big { .. }, z: Big = Big { .. } }

fn p256_inf() -> PtJ {
    return PtJ { .. };
}

fn p256_is_inf(pt: PtJ) -> bool {
    return pt.z.n == 0;
}

// le doublement, formules generales avec a = -3 par la constante montee
fn p256_dbl(pt: PtJ) -> PtJ {
    guard !p256_is_inf(pt) else { return pt; }
    let yy = p256_fm(pt.y, pt.y);
    let zz = p256_fm(pt.z, pt.z);
    // S = 4 x y^2
    let xy2 = p256_fm(pt.x, yy);
    let s = p256_fa(p256_fa(xy2, xy2), p256_fa(xy2, xy2));
    // M = 3 x^2 + a z^4
    let x2 = p256_fm(pt.x, pt.x);
    let m1 = p256_fa(p256_fa(x2, x2), x2);
    let z4 = p256_fm(zz, zz);
    let m = p256_fa(m1, p256_fm(P256_AM, z4));
    let x3 = p256_fs(p256_fm(m, m), p256_fa(s, s));
    // Y3 = M (S - X3) - 8 Y1^4, la puissance passe par (Y1^2)^2
    let y4 = p256_fm(yy, yy);
    let y8 = p256_fa(p256_fa(y4, y4), p256_fa(y4, y4));
    let y3 = p256_fs(p256_fm(m, p256_fs(s, x3)), p256_fa(y8, y8));
    let z3 = p256_fa(p256_fm(pt.y, pt.z), p256_fm(pt.y, pt.z));
    return PtJ { x: x3, y: y3, z: z3 };
}

// l'addition mixte : Jacobian plus un point affine (x2, y2)
fn p256_add_aff(pt: PtJ, x2: Big, y2: Big) -> PtJ {
    if p256_is_inf(pt) {
        var one = big_one();
        return PtJ { x: p256_fin(x2), y: p256_fin(y2), z: mont_in(one, P256_MP) };
    }
    let zz = p256_fm(pt.z, pt.z);
    let u2 = p256_fm(p256_fin(x2), zz);
    let s2 = p256_fm(p256_fin(y2), p256_fm(zz, pt.z));
    let hh = p256_fs(u2, pt.x);
    let rr = p256_fs(s2, pt.y);
    if hh.n == 0 {
        if rr.n == 0 { return p256_dbl(pt); }
        return p256_inf();
    }
    let h2 = p256_fm(hh, hh);
    let h3 = p256_fm(h2, hh);
    let xh2 = p256_fm(pt.x, h2);
    let x3 = p256_fs(p256_fm(rr, rr), p256_fa(p256_fa(h3, xh2), xh2));
    let y3 = p256_fs(p256_fm(rr, p256_fs(xh2, x3)), p256_fm(pt.y, h3));
    let z3 = p256_fm(hh, pt.z);
    return PtJ { x: x3, y: y3, z: z3 };
}

// le scalaire, du bit de poids fort ; le pas se fait sur l'affine
fn p256_mul_aff(ax: Big, ay: Big, k: Big) -> PtJ {
    var acc = p256_inf();
    let bits = big_bitlen(k);
    for i in bits {
        let bit = bits - 1 - i;
        acc = p256_dbl(acc);
        if big_bit(k, bit) == 1 {
            acc = p256_add_aff(acc, ax, ay);
        }
    }
    return acc;
}

// retour a l'affine : l'inversion de z est la seule de tout le calcul.
// mont_inv rend mont(Z^-1) (mont in -> mont out), donc x = fout(mont(X/Z^2))
// et y = fout(mont(Y/Z^3)) avec Z^-3 = Z^-2 x Z^-1
fn p256_to_aff(pt: PtJ) -> Big, Big {
    guard !p256_is_inf(pt) else { return P256_GX, P256_GY; }
    let zinv = mont_inv(pt.z, P256_MP);
    let zinv2 = p256_fm(zinv, zinv);
    let x = p256_fout(p256_fm(pt.x, zinv2));
    let y = p256_fout(p256_fm(pt.y, p256_fm(zinv2, zinv)));
    return x, y;
}

fn big_one() -> Big {
    var b = Big { .. };
    b.w[0] = 1;
    b.n = 1;
    return b;
}

// ECDH : le secret est l'abscisse du produit, en 32 octets gros-boutiste
fn p256_ecdh(d: Big, qx: Big, qy: Big) -> u8[32] {
    let pt = p256_mul_aff(qx, qy, d);
    let x, y = p256_to_aff(pt);
    var out: u8[>..] = [];
    big_to_be(x, out);
    var res: u8[32] = [0; 32];
    if out.len == 32 { res[..].move_from(out[..]); }
    return res;
}

// ---- ECDSA ----

// le e du message : le hash pris comme entier, ramene sous n
fn p256_e_of(msg: const u8[:]) -> Big {
    let h1 = sha256(msg);
    var e = big_from_be(h1[..]);
    if big_cmp(e, P256_N) >= 0 { e = big_sub(e, P256_N); }
    return e;
}

// l'entier DER : zeros de tete partis, zero de tete rendu si le bit haut monte
fn der_int_bytes(v: Big) -> u8[>..] {
    var raw: u8[>..] = [];
    big_to_be(v, raw);
    while raw.len > 1 && raw[0] == 0 { raw.pop(); }
    var padded: u8[>..] = [];
    if raw[0] & 0x80 == 0x80 { padded.push(0); }
    padded.append(raw[..]);
    return padded;
}

fn der_push_len(out: u8[>..]&, len: i64) {
    if len < 128 {
        out.push(len as u8);
        return;
    }
    if len < 256 {
        out.push(0x81);
        out.push(len as u8);
        return;
    }
    out.push(0x82);
    out.push((len >> 8) as u8);
    out.push(len as u8);
}

// la signature deterministe (RFC 6979, HMAC-SHA256), en SEQUENCE
// de deux INTEGER, comme tout le monde l'encode
fn p256_sign(d: Big, msg: const u8[:]) -> u8[>..] {
    let e = p256_e_of(msg);
    var xb: u8[>..] = [];
    big_to_be(d, xb);
    var xb32: u8[32] = [0; 32];
    if xb.len <= 32 { xb32[32 - xb.len..32].move_from(xb[..]); }
    var eb: u8[>..] = [];
    big_to_be(e, eb);
    var eb32: u8[32] = [0; 32];
    if eb.len <= 32 { eb32[32 - eb.len..32].move_from(eb[..]); }
    var v: u8[32] = [1; 32];
    var kk: u8[32] = [0; 32];
    var seed: u8[>..] = [];
    seed.append(v[..]);
    seed.push(0);
    seed.append(xb32[..]);
    seed.append(eb32[..]);
    kk = hmac256(kk, seed[..]);
    v = hmac256(kk, v[..]);
    // la boucle du DRBG : un candidat par tour, jusqu a signature posable
    loop {
        var seed2: u8[>..] = [];
        seed2.append(v[..]);
        seed2.push(0);
        kk = hmac256(kk, seed2[..]);
        v = hmac256(kk, v[..]);
        let kc = big_from_be(v[..]);
        if kc.n > 0 && big_cmp(kc, P256_N) < 0 {
            let pt = p256_mul_aff(P256_GX, P256_GY, kc);
            if !p256_is_inf(pt) {
                let rx, ry = p256_to_aff(pt);
                var r = rx;
                if big_cmp(r, P256_N) >= 0 { r = big_sub(r, P256_N); }
                if r.n > 0 {
                    // s = k^-1 (e + r d) mod n, tout par Montgomery
                    let dm = mont_in(d, P256_MN);
                    let rm = mont_in(r, P256_MN);
                    let rd = mont_out(mont_mul(rm, dm, P256_MN), P256_MN);
                    let s = p256_n_add(e, rd);
                    let km = mont_in(kc, P256_MN);
                    let km1 = mont_inv(km, P256_MN);
                    let sm = mont_in(s, P256_MN);
                    let sfin = mont_out(mont_mul(km1, sm, P256_MN), P256_MN);
                    if sfin.n > 0 {
                        let rb = der_int_bytes(r);
                        let sb = der_int_bytes(sfin);
                        var der: u8[>..] = [];
                        der.push(0x30);
                        der_push_len(der, rb.len + sb.len + 4);
                        der.push(0x02);
                        der_push_len(der, rb.len);
                        der.append(rb[..]);
                        der.push(0x02);
                        der_push_len(der, sb.len);
                        der.append(sb[..]);
                        return der;
                    }
                }
            }
        }
        var seed3: u8[>..] = [];
        seed3.append(v[..]);
        seed3.push(1);
        kk = hmac256(kk, seed3[..]);
        v = hmac256(kk, v[..]);
    }
}

// l'addition modulo n, pour assembler s
fn p256_n_add(a: Big, b: Big) -> Big {
    var r = big_add(a, b);
    if big_cmp(r, P256_N) >= 0 { r = big_sub(r, P256_N); }
    return r;
}

// la verification : DER en entree, le e du hash, deux produits scalaires
fn p256_verify(qx: Big, qy: Big, msg: const u8[:], sig: const u8[:]) -> bool {
    // SEQUENCE { INTEGER r, INTEGER s }, lu a la main
    guard sig.len > 6 && sig[0] == 0x30 else { return false; }
    let slen = der_read_len(sig, 1);
    guard slen > 0 else { return false; }
    // l'entier r ouvre le contenu de la sequence, dont la longueur ferme le tout
    var at2 = 1 + der_len_bytes(sig, 1);
    guard at2 + slen == sig.len && sig[at2] == 0x02 else { return false; }
    let rlen = der_read_len(sig, at2 + 1);
    guard rlen > 0 else { return false; }
    let rstart = at2 + 1 + der_len_bytes(sig, at2 + 1);
    guard rstart + rlen <= sig.len else { return false; }
    let r2pos = rstart + rlen;
    guard r2pos + 2 <= sig.len && sig[r2pos] == 0x02 else { return false; }
    let slen2 = der_read_len(sig, r2pos + 1);
    guard slen2 > 0 else { return false; }
    let sstart = r2pos + 1 + der_len_bytes(sig, r2pos + 1);
    guard sstart + slen2 <= sig.len else { return false; }
    let r = big_from_be(sig[rstart..rstart + rlen]);
    let s = big_from_be(sig[sstart..sstart + slen2]);
    if r.n == 0 || s.n == 0 { return false; }
    if big_cmp(r, P256_N) >= 0 || big_cmp(s, P256_N) >= 0 { return false; }
    let e = p256_e_of(msg);
    // w = s^-1 (mont in -> mont out), u1 = e w, u2 = r w, R = u1 G + u2 Q
    let sm = mont_in(s, P256_MN);
    let wm = mont_inv(sm, P256_MN);
    let em = mont_in(e, P256_MN);
    let rm = mont_in(r, P256_MN);
    let u1 = mont_out(mont_mul(em, wm, P256_MN), P256_MN);
    let u2 = mont_out(mont_mul(rm, wm, P256_MN), P256_MN);
    let p1 = p256_mul_aff(P256_GX, P256_GY, u1);
    let p2 = p256_mul_aff(qx, qy, u2);
    let p2x, p2y = p256_to_aff(p2);
    let rr = p256_add_aff(p1, p2x, p2y);
    if p256_is_inf(rr) { return false; }
    let rx, ry = p256_to_aff(rr);
    var xmod = rx;
    if big_cmp(xmod, P256_N) >= 0 { xmod = big_sub(xmod, P256_N); }
    return big_cmp(xmod, r) == 0;
}

// la longueur DER a partir de sa position ; -1 si elle deborde
fn der_read_len(sig: const u8[:], at: i64) -> i64 {
    guard at < sig.len else { return -1; }
    let first = sig[at];
    if first < 128 { return first; }
    if first == 0x81 {
        guard at + 1 < sig.len else { return -1; }
        return sig[at + 1];
    }
    if first == 0x82 {
        guard at + 2 < sig.len else { return -1; }
        return (sig[at + 1] as i64 << 8) | sig[at + 2];
    }
    return -1;
}

// combien d'octets occupe l'encodage de cette longueur
fn der_len_bytes(sig: const u8[:], at: i64) -> i64 {
    guard at < sig.len else { return 0; }
    let first = sig[at];
    if first < 128 { return 1; }
    if first == 0x81 { return 2; }
    if first == 0x82 { return 3; }
    return 1;
}
