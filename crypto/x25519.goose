// x25519 (RFC 7748) : le corps 2^255-19 sur 8 membres u32, les produits
// en u64 avec repli par 38, et l'echelle de Montgomery en cswap. Les
// vecteurs du RFC sont dans test/x25519.goose, croises avec cryptography.
namespace net;

import std;
import .big;

// le corps 2^255-19, en 8 membres u32 little-endian
struct Fe { w: u32[8] = [0; 8] }

// soustraction puis ajout du module si on a emprunte ; tout le monde
// garde l'invariant "reduit", donc a - b + p tient sur 256 bits
fn fe_sub(a: Fe, b: Fe) -> Fe {
    // a + p - b, calcule directement : aucun emprunt ne sort jamais,
    // puisque a < p et que a + p tient sur 256 bits
    var t = fe_add_raw(a, fe_p());
    var r = Fe { .. };
    var borrow: u64 = 0;
    for i in 8 {
        let av = t.w[i] as u64;
        let bv = b.w[i] + borrow;
        borrow = if av < bv { 1 } else { 0 };
        r.w[i] = (av - bv) as u32;
    }
    fe_reduce_lt_p(r);
    return r;
}

fn fe_add(a: Fe, b: Fe) -> Fe {
    var r = fe_add_raw(a, b);
    fe_reduce_lt_p(r);
    return r;
}

// l'addition brute, avec repli du bit 256 (2^255 vaut 19 chez nous)
fn fe_add_raw(a: Fe, b: Fe) -> Fe {
    var r = Fe { .. };
    var carry: u64 = 0;
    for i in 8 {
        let s = a.w[i] as u64 + b.w[i] + carry;
        r.w[i] = s as u32;
        carry = s >> 32;
    }
    if carry > 0 {
        var c2: u64 = 19 * carry;
        for i in 8 {
            let s = r.w[i] + c2;
            r.w[i] = s as u32;
            c2 = s >> 32;
        }
    }
    return r;
}

// un ou deux passages de soustraction remettent sous le module
fn fe_reduce_lt_p(r: Fe&) {
    let p = fe_p();
    // la sortie des replis peut depasser 2p, quatre passages suffisent
    // et le break evite de payer les suivants
    for _ in 4 {
        if !fe_ge(r, p) { break; }
        fe_sub_in_place(r, p);
    }
}

fn fe_ge(a: Fe, b: Fe) -> bool {
    for i in 8 {
        let wi = a.w[7 - i];
        let wj = b.w[7 - i];
        if wi != wj { return wi > wj; }
    }
    return true;
}

fn fe_sub_in_place(a: Fe&, b: Fe&) {
    var borrow: u64 = 0;
    for i in 8 {
        let av = a.w[i] as u64;
        let bv = b.w[i] + borrow;
        borrow = if av < bv { 1 } else { 0 };
        a.w[i] = (av - bv) as u32;
    }
}

fn fe_p() -> Fe {
    var p = Fe { .. };
    p.w[0] = 0xFFFFFFED;
    for i in 1..7 { p.w[i] = 0xFFFFFFFF; }
    p.w[7] = 0x7FFFFFFF;
    return p;
}

fn fe_zero() -> Fe { return Fe { .. }; }

fn fe_one() -> Fe {
    var f = Fe { .. };
    f.w[0] = 1;
    return f;
}

// le produit 8x8, puis deux replis du haut (38 = 2^255 mod p), puis la
// mise sous le module
fn fe_mul(a: Fe, b: Fe) -> Fe {
    var lo: u32[16] = [0; 16];
    for i in 8 {
        var carry: u64 = 0;
        for j in 8 {
            let acc = lo[i + j] + a.w[i] * b.w[j] as u64 + carry;
            lo[i + j] = acc as u32;
            carry = acc >> 32;
        }
        var k = i + 8;
        while carry > 0 && k < 16 {
            let acc = lo[k] + carry;
            lo[k] = acc as u32;
            carry = acc >> 32;
            k++;
        }
    }
    var r = Fe { .. };
    var carry: u64 = 0;
    for i in 8 {
        let acc = lo[i] + 38 * lo[i + 8] as u64 + carry;
        r.w[i] = acc as u32;
        carry = acc >> 32;
    }
    var c2: u64 = 38 * carry;
    for i in 8 {
        if c2 == 0 { break; }
        let s = r.w[i] + c2;
        r.w[i] = s as u32;
        c2 = s >> 32;
    }
    fe_reduce_lt_p(r);
    return r;
}

fn fe_mul_int(a: Fe, v: u32) -> Fe {
    var r = Fe { .. };
    var carry: u64 = 0;
    for i in 8 {
        let acc = a.w[i] * v as u64 + carry;
        r.w[i] = acc as u32;
        carry = acc >> 32;
    }
    // la retenue au-dessus de 2^256 revient multipliee par 38, comme
    // le reste du repli
    var c2: u64 = 38 * carry;
    for i in 8 {
        if c2 == 0 { break; }
        let s = r.w[i] + c2;
        r.w[i] = s as u32;
        c2 = s >> 32;
    }
    fe_reduce_lt_p(r);
    return r;
}

// l'inverse par Fermat : p - 2 en exposant, par carres successifs
fn fe_inv(a: Fe) -> Fe {
    var e = fe_p();
    e.w[0] -= 2;
    var acc = fe_one();
    for i in 255 {
        let bit = 254 - i;
        acc = fe_mul(acc, acc);
        if (e.w[bit / 32] >> (bit % 32)) & 1 == 1 {
            acc = fe_mul(acc, a);
        }
    }
    return acc;
}

fn fe_load(u: u8[:]) -> Fe {
    var f = Fe { .. };
    for i in 8 {
        var word: u32 = 0;
        for s in 4 {
            word |= (u[i * 4 + s] as u32) << (8 * s);
        }
        f.w[i] = word;
    }
    return f;
}

fn fe_bytes(f: Fe) -> u8[32] {
    var le: u8[32] = [0; 32];
    for i in 8 {
        for s in 4 {
            le[i * 4 + s] = (f.w[i] >> (8 * s)) as u8;
        }
    }
    return le;
}

// l'echange conditionnel, constant en temps
fn fe_cswap(swap: u8, a: Fe&, b: Fe&) {
    let mask: u32 = 0 - swap as u32;
    for i in 8 {
        let t = mask & (a.w[i] ^ b.w[i]);
        a.w[i] ^= t;
        b.w[i] ^= t;
    }
}

// la fonction du RFC : scalaire clampé, coordonnee u sans son bit haut,
// 254 doubles de l'echelle, et le quotient x2/z2 a l'arrivee
fn x25519(scalar: const u8[:], ucoord: const u8[:]) -> u8[32] {
    var k: u8[32] = [0; 32];
    k[..].move_from(scalar[..32]);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    var u: u8[32] = [0; 32];
    u[..].move_from(ucoord[..32]);
    u[31] &= 127;
    let x1 = fe_load(u);
    var x2 = fe_one();
    var z2 = fe_zero();
    var x3 = x1;
    var z3 = fe_one();
    var swap: u8 = 0;
    for t in 255 {
        let bit = 254 - t;
        let kbt = (k[bit / 8] >> (bit % 8)) & 1;
        swap ^= kbt;
        fe_cswap(swap, x2, x3);
        fe_cswap(swap, z2, z3);
        swap = kbt;
        let aa = fe_mul(fe_add(x2, z2), fe_add(x2, z2));
        let bb = fe_mul(fe_sub(x2, z2), fe_sub(x2, z2));
        let ee = fe_sub(aa, bb);
        let da = fe_mul(fe_sub(x3, z3), fe_add(x2, z2));
        let cb = fe_mul(fe_add(x3, z3), fe_sub(x2, z2));
        x3 = fe_mul(fe_add(da, cb), fe_add(da, cb));
        z3 = fe_mul(x1, fe_mul(fe_sub(da, cb), fe_sub(da, cb)));
        x2 = fe_mul(aa, bb);
        z2 = fe_mul(ee, fe_add(aa, fe_mul_int(ee, 121665)));
    }
    fe_cswap(swap, x2, x3);
    fe_cswap(swap, z2, z3);
    let ratio = fe_mul(x2, fe_inv(z2));
    return fe_bytes(ratio);
}
