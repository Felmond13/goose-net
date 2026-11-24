// Les adresses : le type public Addr, leur texte, et les sockaddr bruts
// que bind/connect/accept échangent avec le noyau.
namespace net;
import std;
import ffi;
import binary;
import platform;
import libc;

// Une adresse IP avec son port : la famille, les octets tels qu'ils
// partent sur le fil (v4 dans les quatre premiers), le port en ordre hôte.
// C'est le type public du module, celui que write_to et read_from échangent.
struct Addr { family: i32 = 0, port: u16 = 0, bytes: u8[16] = [0; 16] }

fn format(out: u8[>..]&, a: Addr) {
    if a.family == AF_INET6 { out.push('['); }
    addr_text(a.family, a.bytes[..], out);
    if a.family == AF_INET6 { out.push(']'); }
    format(out, ":", a.port);
}

// L'adresse en texte, par inet_ntop — écrire un rendu IPv6 canonique pour
// ça n'avait aucun sens.
fn addr_text(family: i32, addr: const u8[:], out: u8[>..]&) {
    var buf: u8[64] = [0; 64];
    let p = inet_ntop(family, addr[0], buf[0], 64);
    if p != 0 {
        if ffi::cstr(p, out) { return; }
    }
    out.append("?");
}

// Le texte vers les octets du fil, v4 ou v6, par inet_pton. Ça ne touche
// jamais au résolveur : un littéral ou BadAddr.
fn parse_addr(host: const u8[:]) -> Addr, Err {
    var a = Addr { .. };
    var hz: u8[>..] = [];
    hz.append(host);
    hz.push(0);                          // inet_pton veut du NUL-terminal
    if inet_pton(AF_INET, hz[0], a.bytes[0]) == 1 {
        a.family = AF_INET;
        return a, Err.None;
    }
    if inet_pton(AF_INET6, hz[0], a.bytes[0]) == 1 {
        a.family = AF_INET6;
        return a, Err.None;
    }
    return a, Err.BadAddr;
}

// Une Addr prête pour write_to : littéral IP ou nom résolu (le premier
// candidat du résolveur).
fn addr(host: const u8[:], port: i64) -> Addr, Err {
    var a, aerr = parse_addr(host);
    if aerr != Err.None {
        var cands: Addr[>..] = [];
        aerr = resolve(host, 0, cands);
        if aerr != Err.None { return a, aerr; }
        if cands.len == 0 { return a, Err.BadAddr; }
        a = cands[0];
    }
    if port < 0 || port > 65535 { return a, Err.BadPort; }
    a.port = port as u16;
    return a, Err.None;
}

// Le sockaddr prêt pour bind/connect/sendto, depuis une Addr. Chez Darwin,
// un sockaddr commence par sa_len puis la famille sur 8 bits ; chez Linux,
// la famille est un u16 sans champ longueur. Le port est toujours à
// l'offset 2 et l'adresse v6 toujours à 8, ce qui rend le reste commun.
fn sockaddr(a: Addr, out: u8[>..]&) {
    out.clear();
    if OS_DARWIN {
        out.push((if a.family == AF_INET6 { 28 } else { 16 }) as u8);
        out.push(a.family as u8);
    } else {
        binary::write_u16le(out, a.family as u16);
    }
    binary::write_u16be(out, a.port);
    if a.family == AF_INET6 {
        for _ in 4 { out.push(0); }              // flowinfo
        out.append(a.bytes[..16]);
        for _ in 4 { out.push(0); }              // scope : fe80::%eth0 reste à faire
    } else {
        out.append(a.bytes[..4]);
        for _ in 8 { out.push(0); }              // sin_zero
    }
}

// Le chemin inverse, après accept/recvfrom/getsockname.
fn sockaddr_addr(sa: const u8[:]) -> Addr {
    var a = Addr { .. };
    a.family = sa_family(sa);
    let p, ok = binary::read_u16be(sa, 2);
    if ok { a.port = p; }
    if a.family == AF_INET { a.bytes[..4].move_from(sa[4..8]); }
    if a.family == AF_INET6 { a.bytes[..16].move_from(sa[8..24]); }
    return a;
}

fn sa_family(sa: const u8[:]) -> i32 {
    if OS_DARWIN {
        let f, _ = binary::read_u8(sa, 1);
        return f;
    }
    let f, _ = binary::read_u16le(sa, 0);
    return f;
}

// après bind, le port réel : le 0 du demandeur devient ce que l'OS a choisi
fn bound_port(fd: i32) -> i64 {
    var sa:    u8[64] = [0; 64];
    var salen: u32    = 64;
    if getsockname(fd, sa[0], salen) != 0 { return 0; }
    let p, _ = binary::read_u16be(sa[..], 2);
    p
}
