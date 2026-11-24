// Les vecteurs P-256 viennent d'une implementation de reference en Python
// (points affines, ECDSA a nonce fixe). Le sens inverse est verifie aussi :
// la signature produite ici est relue par Python, cf. test/verif_sig.py.
//   goose run test/p256.goose
namespace net;
import net from "..";
import std;

fn ::main() { net::pv(); }

fn pv() {
    var fails = 0;
    let da = big_from_be(unhex("cf3b77b7aee6a7f4cb088e9c35a9437a9f287d8a352b9f1b1a5503cd285dcdd0")[..]);
    let db = big_from_be(unhex("2fefd5101220058c0aee6c9084ac56b008b087ac3466ba692c55221ae073cf4e")[..]);
    let gx = big_from_be(unhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")[..]);
    let gy = big_from_be(unhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")[..]);
    let qax = big_from_be(unhex("a27c0f054501a4388d43091009623e72964e89109005105ac6af702943901b23")[..]);
    let qay = big_from_be(unhex("10f77490b3e9cc28b85af601d41c360fb942b9dfeae873cbec6a63ecbbdf2397")[..]);
    let qbx = big_from_be(unhex("aae7a00cfa9dec8b0472ffa0ac8da4406d11dd930b1db45dc9a73763818e688a")[..]);
    let qby = big_from_be(unhex("5df7bea46a35a77ec0b2c1b316b20e5e6908efa9131ef0b2bfdcbfadff2869e7")[..]);

    let q = p256_ecdh(da, gx, gy);
    fails += check("p256 pubkey A", hex_eq(q, "a27c0f054501a4388d43091009623e72964e89109005105ac6af702943901b23"));

    let s1 = p256_ecdh(da, qbx, qby);
    fails += check("p256 ecdh A", hex_eq(s1, "e9c67c719a8b99aae19af38ab93f4f710265209cea7f37013e492c646fbfc005"));
    let s2 = p256_ecdh(db, qax, qay);
    fails += check("p256 ecdh B", hex_eq(s2, "e9c67c719a8b99aae19af38ab93f4f710265209cea7f37013e492c646fbfc005"));

    let msg: const u8[:] = "le renard rapide court pres du chien paresseux";
    // la signature faite par Python (nonce fixe) doit passer la verification goose
    let pysig = unhex("30440220712529253a7209378897eb77000056f8761cabb9afd4e8412f8cf58f29bc1235022025c48a4eac77a350f10534542057d57ba8220e38f39719bd6d5b05cab42e7c34");
    fails += check("p256 verify py", p256_verify(qax, qay, msg, pysig));
    var bad: u8[>..] = [];
    bad.append(pysig[..]);
    bad[bad.len - 1] ^= 1;
    fails += check("p256 verify tampe", !p256_verify(qax, qay, msg, bad));

    // la signature goose se reverifie chez goose ; Python la relue a part
    let sig = p256_sign(da, msg);
    fails += check("p256 sign+verify", p256_verify(qax, qay, msg, sig));
    print("sig:", tohex(sig));

    if fails == 0 { print("vecteurs p256 ok"); } else { print(fails, " FAILURES"); exit(1); }
}

fn check(name: const u8[:], ok: bool) -> i32 {
    if ok { print("ok  ", name); return 0; }
    print("FAIL", name);
    return 1;
}

fn hex_eq(data: const u8[:], hex: const u8[:]) -> bool {
    if data.len * 2 != hex.len { return false; }
    for i in data.len {
        let hi = nibble(hex[i * 2]);
        let lo = nibble(hex[i * 2 + 1]);
        if hi < 0 || lo < 0 { return false; }
        if data[i] != (hi as u8 << 4) | lo as u8 { return false; }
    }
    return true;
}

fn tohex(data: const u8[:]) -> u8[>..] {
    const digits: const u8[:] = "0123456789abcdef";
    var out: u8[>..] = [];
    for i in data.len {
        out.push(digits[data[i] >> 4]);
        out.push(digits[data[i] & 15]);
    }
    return out;
}

fn nibble(c: u8) -> i64 {
    if c >= 48 && c <= 57 { return c - 48; }
    if c >= 97 && c <= 102 { return c - 97 + 10; }
    if c >= 65 && c <= 70 { return c - 65 + 10; }
    return -1;
}

fn unhex(hex: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < hex.len {
        out.push((nibble(hex[i]) as u8 << 4) | nibble(hex[i + 1]) as u8);
        i += 2;
    }
    return out;
}
