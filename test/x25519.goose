// Les vecteurs x25519 du RFC 7748 6.1, croises avec cryptography.
//   goose run test/x25519.goose
namespace net;
import net from "..";
import std;

fn ::main() { net::xv(); }

fn xv() {
    var fails = 0;
    var ap = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    var bp = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6321e792c1c36ed4204");
    var nine = unhex("0900000000000000000000000000000000000000000000000000000000000000");
    var apub = x25519(ap[..], nine);
    var bpub = x25519(bp[..], nine);
    fails += check("x25519 a_pub", hex_eq(apub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    fails += check("x25519 b_pub", hex_eq(bpub, "afdf3e7d0c0d938c4d8675d5193feb67d1ded0ac4fadef65a28a9b2b0b80b531"));
    var sec = x25519(ap[..], bpub);
    fails += check("x25519 shared", hex_eq(sec, "294b4bad6c4ac02fdd85fa235177fb1d7ab318836503d461bb03cfb5d2a8f44a"));
    if fails == 0 { print("vecteurs x25519 ok"); } else { print(fails, " FAILURES"); exit(1); }
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
