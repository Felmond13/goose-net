// Le gros entier dont RSA et ECDSA ont besoin : membres u32 en
// little-endian, capacite fixe (RSA-4096 et le produit intermediaire de
// Montgomery tiennent dans BIGW), et une reduction de Montgomery pour le
// modpow. Lent et simple ; on veut d abord dire correct.
namespace net;

import std;

// 260 membres = 8320 bits : une valeur de 4096 bits, un produit
// intermediaire de 8192, et la marge qui va avec.
const BIGW = 260;

struct Big { w: u32[BIGW] = [0; BIGW], n: i32 = 0 }

// supprime les membres de tete qui ne servent a rien
fn big_norm(b: Big&) {
    while b.n > 0 && b.w[b.n - 1] == 0 { b.n--; }
}

fn big_from_be(data: const u8[:]) -> Big {
    var b = Big { .. };
    b.n = ((data.len + 3) / 4) as i32;
    for i in data.len {
        // les octets les plus a la fin peuplent les membres les plus bas
        let pos = data.len - 1 - i;
        b.w[pos / 4] |= (data[i] as u32) << ((pos % 4) * 8);
    }
    big_norm(b);
    return b;
}

fn big_from_hex(hex: const u8[:]) -> Big {
    // les valeurs des courbes se lisent mieux en hex ; par paquets de 8
    var bytes: u8[>..] = [];
    var at = 0;
    if hex.len % 2 == 1 { bytes.push(nibv(hex[0])); at = 1; }
    while at + 1 < hex.len {
        bytes.push((nibv(hex[at]) << 4) | nibv(hex[at + 1]));
        at += 2;
    }
    return big_from_be(bytes[..]);
}

fn nibv(c: u8) -> u8 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return 0;
}

// l'octet le plus significatif d'abord, sans zero de tete (un zero rend
// un octet unique, pour ne jamais manger un 00 de separation DER)
fn big_to_be(b: Big, out: u8[>..]&) {
    var t = b;
    big_norm(t);
    if t.n == 0 { out.push(0); return; }
    var started = false;
    for i in t.n {
        let wi = t.w[t.n - 1 - i];
        for s in 4 {
            let byte = (wi >> (24 - 8 * s)) as u8;
            if started || byte != 0 {
                out.push(byte);
                started = true;
            }
        }
    }
}

fn big_bitlen(b: Big) -> i64 {
    var t = b;
    big_norm(t);
    if t.n == 0 { return 0; }
    let top = t.w[t.n - 1];
    var k = 31;
    while k > 0 && (top >> k) & 1 == 0 { k--; }
    return (t.n - 1) as i64 * 32 + k + 1;
}

fn big_bit(b: Big, i: i64) -> u32 {
    return (b.w[i / 32] >> (i % 32)) & 1;
}

fn big_cmp(a: Big, b: Big) -> i64 {
    var ta = copy(a);
    var tb = copy(b);
    big_norm(ta);
    big_norm(tb);
    if ta.n != tb.n { return if ta.n > tb.n { 1 } else { -1 }; }
    for i in ta.n {
        let wa = ta.w[ta.n - 1 - i];
        let wb = tb.w[tb.n - 1 - i];
        if wa != wb { return if wa > wb { 1 } else { -1 }; }
    }
    return 0;
}

fn big_add(a: Big, b: Big) -> Big {
    var r = Big { .. };
    let n = max(a.n, b.n) + 1;
    var carry: u32 = 0;
    for i in n {
        let s = a.w[i] as u64 + b.w[i] + carry;
        r.w[i] = s as u32;
        carry = (s >> 32) as u32;
    }
    r.n = n;
    big_norm(r);
    return r;
}

// a - b, a >= b suppose (les appels le garantissent tous)
fn big_sub(a: Big, b: Big) -> Big {
    var r = Big { .. };
    var borrow: u64 = 0;
    for i in a.n {
        let bi = if i < b.n { b.w[i] as u64 } else { 0 };
        let av = a.w[i] as u64;
        let sv = bi + borrow;
        borrow = if av < sv { 1 } else { 0 };
        r.w[i] = (av - sv) as u32;
    }
    r.n = a.n;
    big_norm(r);
    return r;
}

fn big_mul(a: Big, b: Big) -> Big {
    var r = Big { .. };
    if a.n == 0 || b.n == 0 { return r; }
    r.n = a.n + b.n;
    for i in a.n {
        var carry: u64 = 0;
        for j in b.n {
            let acc = r.w[i + j] + a.w[i] * b.w[j] as u64 + carry;
            r.w[i + j] = acc as u32;
            carry = acc >> 32;
        }
        var k = i + b.n;
        while carry > 0 {
            let acc = r.w[k] + carry;
            r.w[k] = acc as u32;
            carry = acc >> 32;
            k++;
        }
    }
    big_norm(r);
    return r;
}

// division binaire longue : quotient et reste
fn big_divmod(a: Big, b: Big) -> Big, Big {
    var q = Big { .. };
    var rem = Big { .. };
    let bits = big_bitlen(a);
    for i in bits {
        let bit = bits - 1 - i;
        // rem = rem << 1 | bit
        rem = big_shl1_bit(rem, big_bit(a, bit));
        if big_cmp(rem, b) >= 0 {
            rem = big_sub(rem, b);
            q.w[bit / 32] |= 1 << (bit % 32);
        }
    }
    q.n = ((bits + 31) / 32) as i32;
    big_norm(q);
    big_norm(rem);
    return q, rem;
}

fn big_shl1_bit(b: Big, bit: u32) -> Big {
    var r = Big { .. };
    let words = b.n + 1;
    for i in words {
        let low = b.w[i] << 1;
        let carry = if i > 0 { b.w[i - 1] >> 31 } else { 0 };
        r.w[i] = low | carry;
    }
    r.w[0] |= bit;
    r.n = words;
    big_norm(r);
    return r;
}

// ---- Montgomery ----

// n impair ; r = 2^(32k) avec k = mots de n ; n0 = -n^-1 mod 2^32 ;
// r1 = r mod n ; r2 = r^2 mod n
struct Mont { modn: Big = Big { .. }, n0: u32 = 0, r1: Big = Big { .. }, r2: Big = Big { .. }, words: i32 = 0 }

fn mont_setup(modn: Big) -> Mont {
    var m = Mont { .. };
    m.modn = copy(modn);
    m.words = modn.n;
    // Newton sur Hensel : inv <- inv * (2 - n * inv), tout modulo 2^32
    var inv: u32 = 1;
    for _ in 5 {
        inv = inv * (2 - modn.w[0] * inv);
    }
    m.n0 = 0 - inv;
    // r mod n : la chaine de bits 1 suivie de 32k zeros, divisee par n
    var one: u8[>..] = [];
    one.push(1);
    for _ in modn.n * 4 { one.push(0); }
    let rb = big_from_be(one[..]);
    let q, r1 = big_divmod(rb, modn);
    m.r1 = r1;
    let rr = big_mul(r1, r1);
    let q2, r2 = big_divmod(rr, modn);
    m.r2 = r2;
    return m;
}

// REDC sur le produit : n0 tire le multiple de n qui rend le bas nul
fn mont_mul(a: Big, b: Big, m: Mont&) -> Big {
    let k = m.words;
    var prod = big_mul(a, b);
    for i in k {
        let u = prod.w[i] * m.n0;
        var carry: u64 = 0;
        for j in k {
            let acc = prod.w[i + j] + m.modn.w[j] * u as u64 + carry;
            prod.w[i + j] = acc as u32;
            carry = acc >> 32;
        }
        // la retenue monte au dela du produit, chez les membres suivants
        var t = i + k;
        while carry > 0 {
            let acc = prod.w[t] + carry;
            prod.w[t] = acc as u32;
            carry = acc >> 32;
            t++;
        }
    }
    var r = Big { .. };
    for i in k { r.w[i] = prod.w[i + k]; }
    // le quotient peut deborder sur un mot de plus : sans lui, la
    // comparaison avec le module rate la soustraction finale
    r.w[k] = prod.w[2 * k];
    r.n = k + 1;
    big_norm(r);
    if big_cmp(r, m.modn) >= 0 { r = big_sub(r, m.modn); }
    return r;
}

// entre dans le domaine de Montgomery
fn mont_in(x: Big, m: Mont&) -> Big {
    return mont_mul(x, m.r2, m);
}

// en sort : le produit par 1 degage le facteur R
fn mont_out(x: Big, m: Mont&) -> Big {
    var one = Big { .. };
    one.w[0] = 1;
    one.n = 1;
    return mont_mul(x, one, m);
}

// carré-et-multiplication, du bit de poids fort au dernier ; base et
// rendu vivent dans le domaine de Montgomery
fn mont_powmod(base: Big, e: Big, m: Mont&) -> Big {
    var acc = m.r1;
    let bits = big_bitlen(e);
    for i in bits {
        let bit = bits - 1 - i;
        acc = mont_mul(acc, acc, m);
        if big_bit(e, bit) == 1 {
            acc = mont_mul(acc, base, m);
        }
    }
    return acc;
}

// l'inverse par Fermat, pour un module premier
fn mont_inv(x: Big, m: Mont&) -> Big {
    var two = Big { .. };
    two.w[0] = 2;
    two.n = 1;
    let em2 = big_sub(m.modn, two);
    // x arrive et repart dans le domaine de Montgomery : le powmod
    // equilibre deja les facteurs R de son cote
    return mont_powmod(x, em2, m);
}
