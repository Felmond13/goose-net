// Les vecteurs des primitives, générés avec hashlib/hmac d'un côté, du
// code Goose de l'autre. Un fichier racine à lui tout seul :
//   goose run test/vectors.goose
namespace net;
import net from "..";

fn vectors() {
    var fails = 0;
    // SHA-256 : "abc", le vide, et les deux longuers qui encadrent le
    // bourrage à cheval sur deux blocs
    fails += check("sha256 abc", hex_eq(sha256("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    fails += check("sha256 empty", hex_eq(sha256(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    var a55: u8[>..] = [];
    for i in 55 { a55.push('a'); }
    var a56: u8[>..] = [];
    for i in 56 { a56.push('a'); }
    fails += check("sha256 55a", hex_eq(sha256(a55[..]), "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"));
    fails += check("sha256 56a", hex_eq(sha256(a56[..]), "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"));

    // le streaming donne la même chose que le one-shot, bloc par bloc
    var st = sha256_init();
    for i in 10 {
        sha256_update(st, a55[i * 5..i * 5 + 5]);
    }
    sha256_update(st, a55[50..]);
    var streamed: u8[32] = [0; 32];
    sha256_final(st, streamed);
    fails += check("sha256 streaming", hex_eq(streamed, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"));

    fails += check("sha384 abc", hex_eq(sha384("abc"), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"));
    fails += check("sha512 abc", hex_eq(sha512("abc"), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));

    // HMAC-SHA256 : RFC 4231 cas 2, et une clé plus longue que le bloc
    fails += check("hmac256 jefe", hex_eq(hmac256("Jefe", "what do ya want for nothing?"), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    var bigkey: u8[>..] = [];
    for i in 131 { bigkey.push(0xaa); }
    fails += check("hmac256 longkey", hex_eq(hmac256(bigkey[..], "Test Using Larger Than Block-Size Key - Hash Key First"), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));

    // HKDF-SHA256 : RFC 5869 cas 1 et cas 3 (salt et info vides)
    var ikm: u8[>..] = [];
    for i in 22 { ikm.push(0x0b); }
    var salt: u8[>..] = [];
    for i in 13 { salt.push(i as u8); }
    var info: u8[>..] = [];
    for i in 10 { info.push((0xf0 + i) as u8); }
    var prk = hkdf_extract256(salt[..], ikm[..]);
    var okm: u8[>..] = [];
    hkdf_expand256(prk, info[..], 42, okm);
    fails += check("hkdf case1", hex_eq(okm[..], "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    var prk3 = hkdf_extract256("", ikm[..]);
    var okm3: u8[>..] = [];
    hkdf_expand256(prk3, "", 42, okm3);
    fails += check("hkdf case3", hex_eq(okm3[..], "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));

    // AES-128, le bloc du FIPS-197 annexe C.1
    var ak = unhex("000102030405060708090a0b0c0d0e0f");
    var ab = unhex("00112233445566778899aabbccddeeff");
    var aes = aes128_init(ak[..]);
    var ob: u8[16] = [0; 16];
    aes128_block(aes, ab[..], ob);
    fails += check("aes128 fips197", hex_eq(ob, "69c4e0d86a7b0430d8cdb78070b4c55a"));

    // GCM, cas 1 du spec NIST : tout a zero
    var gkey: u8[16]  = [0; 16];
    var giv:  u8[12]  = [0; 12];
    var gpt:  u8[16]  = [0; 16];
    var gout: u8[>..] = [];
    var tag = gcm128_seal(gkey[..], giv[..], "", gpt[..], gout);
    fails += check("gcm tc1 ct", hex_eq(gout[..], "0388dace60b6a392f328c2b971b2fe78"));
    fails += check("gcm tc1 tag", hex_eq(tag, "ab6e47d42cec13bdf53a67b21257bddf"));

    // le vecteur determine du generateur, avec aad, et le chemin ouvert
    var k2 = unhex("030a11181f262d343b424950575e656c");
    var iv2 = unhex("010c17222d38434e59646f7a");
    var aad2 = unhex("021f3c597693b0cdea0724415e7b98b5d2ef0c29");
    var pt2 = unhex("05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0adbac7d4e1eefb08");
    var out2: u8[>..] = [];
    var tag2 = gcm128_seal(k2[..], iv2[..], aad2[..], pt2[..], out2);
    fails += check("gcm tc4 ct", hex_eq(out2[..], "6aac70db3c254fd42f03f90549616a3e207a0eeb8f5d3026db3071bd9a93a8d95eeb97d1d770a03800ce329774c8b115f5286441a4dd0165d5c3b93345f08719e4132233485a6a27720d96f237551118"));
    fails += check("gcm tc4 tag", hex_eq(tag2, "3e5ac431248b8e60dea40b1252f50d00"));
    var back: u8[>..] = [];
    let okopen = gcm128_open(k2[..], iv2[..], aad2[..], out2[..], tag2, back);
    fails += check("gcm open ok", okopen && back[..] == pt2[..]);
    tag2[0] ^= 1;
    let badopen = gcm128_open(k2[..], iv2[..], aad2[..], out2[..], tag2, back);
    fails += check("gcm open tampe", !badopen && back.len == 0);

    // bignum : le modpow RSA public sur une vraie cle 2048, s^e == m
    var n = big_from_hex("885a50466027b550f56024b08a4c3d40263d4e71c60162c6dd8cff60bf6a85b019d6d8bc454b253ed269707dd6a00734807f626f0d15474c1a0da653996d5ca8fe270736e9c0f84adb654f7547f5403fc73470a62c2d1915d8c60c9786ca8a18b32606cd3af2d55fdc86f9aa54f3fe1796d190c7fe848fc6a0fa055dd8d94fbfe13ca6ca42e9aca732ce33972929cb972df24ebbb5d5f85974ea5d891edebd97ce06a24213c7cbcab9f766d0808055932781a2454d055d4ec4beb0dddf11724683e0e363bfddbc25aaca519fa682b8c3d82a0f3ab03ac53a4b1ff543b285c1556f5d9c6ee41e7ac9fed9a0906bb0411cbdf5b4d0bd8ca4db5ada8420bc38380f");
    var s = big_from_hex("4d914b72a25a396d3873e990689872b1f42ffbb40f8598d68138aade18c6215cdd625f7429d7502476644c725c72efd4af9ad883719662a045afa8bb63085a07ed16f0bded0486538d111b4b4ed1d0f8f22e3e94f82f8397287f18690142e72d71370e1c45f0a34273d47b2cb15cf115ff7e2a2a0a394f6ced08d8f9c91dc451492c486f25faaa41ba9bf42614774df1a9adef293556ff48d8a1bf28e4dff5913372bd0a7705f41ac09dddecb5eefa93af495254e1ea6deeb6d89c1a88d92d4f534991e15254f52ca196f27355b793bb06d08f2e2a4ed017422317ccbea9cfca0ba2c676be4d321d15bf009b8870974b18ca6bc6017c83b2dc50478d49890e2d");
    var m = big_from_hex("3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89452821e638d01377be5466cf34e90c6cc0ac29b8c97c501dd059fe28302ce0");
    let mn = mont_setup(n);
    var sm = mont_in(s, mn);
    var e65537 = big_from_hex("010001");
    var r = mont_powmod(sm, e65537, mn);
    r = mont_out(r, mn);
    fails += check("rsa modpow 2048", big_cmp(r, m) == 0);

    // aller-retour octets pour une valeur impaire de longueur
    var odd = big_from_hex("800102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00ff");
    var oddout: u8[>..] = [];
    big_to_be(odd, oddout);
    var oddback = big_from_be(oddout[..]);
    fails += check("big to/from be", big_cmp(oddback, odd) == 0);

    // l arithmetique de base, valeurs verifiees par python
    var a1 = big_from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
    var b1 = big_from_hex("2");
    var sum = big_add(a1, b1);
    fails += check("big add", big_cmp(sum, big_from_hex("10000000000000000000000000000000000000000000000000000000000000000")) == 0);
    var diff = big_sub(sum, b1);
    fails += check("big sub", big_cmp(diff, a1) == 0);
    var p12 = big_mul(big_from_hex("1234567890abcdef"), big_from_hex("fedcba0987654321"));
    fails += check("big mul", big_cmp(p12, big_from_hex("121fa000a3723a57c24a442fe55618cf")) == 0);
    let q, rr = big_divmod(big_from_hex("123456789abcdef0123456789abcdef0"), big_from_hex("deadbeef"));
    fails += check("big divmod q", big_cmp(q, big_from_hex("14edb42717dce03fca52ec12")) == 0);
    fails += check("big divmod r", big_cmp(rr, big_from_hex("7f31e22")) == 0);

    if fails == 0 { print("tous les vecteurs ok"); } else { print(fails, " FAILURES"); exit(1); }
}

// compte un échec, affiche une ligne ; rend 1 ou 0 pour additionner
fn check(name: const u8[:], ok: bool) -> i32 {
    if ok { print("ok  ", name); return 0; }
    print("FAIL", name);
    return 1;
}

// la comparaison en hexadécimal : ça s'affiche, ça se relit
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

fn nibble(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

fn ::main() { net::vectors(); }

// une chaine hex en octets, pour poser les vecteurs lisiblement
fn unhex(hex: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < hex.len {
        let hi = nibble(hex[i]);
        let lo = nibble(hex[i + 1]);
        out.push((hi as u8 << 4) | lo as u8);
        i += 2;
    }
    return out;
}
