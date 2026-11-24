// UDP : datagrammes, sockets liées ou connectées, et le multicast v4/v6.
// Un datagramme part entier ou pas du tout (le noyau ne coupe pas), donc
// write/write_to rendent juste Err ; un datagramme plus gros que le
// tampon serait tronqué sans prévenir, d'où des tampons à la taille
// maximale réelle.
namespace net;
import std;
import binary;
import platform;
import libc;
import addr;
import dns;

struct Udp { fd: i32, family: i32 = 0, port: u16 = 0, addr: u8[16] = [0; 16], toms: i32 = -1, rbuf: u8[>..] }

// Pas de SO_REUSEADDR ici : sur UDP ça autorise deux bindings, c'est le
// travail de REUSEPORT et on ne le fait pas à moitié.
fn udp_bind(host: const u8[:], port: i64, reuseport: bool = false) -> Udp, Err {
    var a, aerr = parse_addr(host);
    if aerr != Err.None { return Udp { fd: -1, .. }, aerr; }
    if port < 0 || port > 65535 { return Udp { fd: -1, .. }, Err.BadPort; }
    a.port = port as u16;
    let fd, oerr = sock_open(a.family, SOCK_DGRAM);
    if oerr != Err.None { return Udp { fd: -1, .. }, oerr; }
    if reuseport {
        let one: i32 = 1;
        if setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, one, 4) != 0 {
            let e = syserr("sockopt");
            close(fd);
            return Udp { fd: -1, .. }, e;
        }
    }
    var sa: u8[>..] = [];
    sockaddr(a, sa);
    if bind(fd, sa[0], sa.len as u32) != 0 {
        let e = syserr("bind");
        close(fd);
        return Udp { fd: -1, .. }, e;
    }
    a.port = bound_port(fd) as u16;
    return Udp { fd: fd, family: a.family, port: a.port, .. }, Err.None;
}

// Une socket UDP connectée : le peer est fixé, read/write parlent à lui
// seul et le noyau remonte les ICMP port unreachable en ECONNREFUSED.
fn udp_dial(host: const u8[:], port: i64, secs: f64 = 0) -> Udp, Err {
    let fd, a, err = dial(host, port, true, secs);
    if err != Err.None { return Udp { fd: -1, .. }, err; }
    return Udp { fd: fd, family: a.family, port: a.port, addr: a.bytes, .. }, Err.None;
}

// Côté UDP connecté : recv ne rend 0 que pour un datagramme vide, et ça
// n'a rien d'une fermeture — personne ne ferme rien en UDP.
fn read(u: Udp&) -> const u8[:], Err {
    let r = wait_ready(u.fd, POLLIN, u.toms);
    if r == 0 { u.rbuf.clear(); return u.rbuf[..], Err.TimedOut; }
    if r < 0 { u.rbuf.clear(); return u.rbuf[..], syserr("poll"); }
    u.rbuf.clear();
    u.rbuf.resize(UDPMAX, 0);
    let n = recv(u.fd, u.rbuf[0], UDPMAX, 0);
    if n < 0 {
        u.rbuf.clear();
        if errno_now() == EAGAIN { return u.rbuf[..], Err.TimedOut; }
        return u.rbuf[..], syserr("recv");
    }
    u.rbuf.resize(n);
    return u.rbuf[..], Err.None;
}

// Le datagramme reçu, plus l'adresse de qui l'a envoyé.
fn read_from(u: Udp&) -> const u8[:], Addr, Err {
    let r = wait_ready(u.fd, POLLIN, u.toms);
    if r == 0 { u.rbuf.clear(); return u.rbuf[..], Addr { .. }, Err.TimedOut; }
    if r < 0 { u.rbuf.clear(); return u.rbuf[..], Addr { .. }, syserr("poll"); }
    u.rbuf.clear();
    u.rbuf.resize(UDPMAX, 0);
    var sa:    u8[64] = [0; 64];
    var salen: u32    = 64;
    let n = recvfrom(u.fd, u.rbuf[0], UDPMAX, 0, sa[0], salen);
    if n < 0 {
        u.rbuf.clear();
        let e = if errno_now() == EAGAIN { Err.TimedOut } else { syserr("recvfrom") };
        return u.rbuf[..], Addr { .. }, e;
    }
    u.rbuf.resize(n);
    return u.rbuf[..], sockaddr_addr(sa[..]), Err.None;
}

// Nécessite une socket connectée : udp_bind ne fixe pas de peer, pour lui
// c'est write_to.
fn write(u: Udp&, data: const u8[:]) -> Err {
    let r = wait_ready(u.fd, POLLOUT, u.toms);
    if r == 0 { return Err.TimedOut; }
    if r < 0 { return syserr("poll"); }
    var zero: u8 = 0;
    let p: const u8& = if data.len > 0 { data[0] } else { zero };
    if send(u.fd, p, data.len as u64, 0) < 0 {
        if errno_now() == EAGAIN { return Err.TimedOut; }
        return syserr("send");
    }
    return Err.None;
}

fn write_to(u: Udp&, data: const u8[:], to: Addr) -> Err {
    let r = wait_ready(u.fd, POLLOUT, u.toms);
    if r == 0 { return Err.TimedOut; }
    if r < 0 { return syserr("poll"); }
    var sa: u8[>..] = [];
    sockaddr(to, sa);
    var zero: u8 = 0;
    let p: const u8& = if data.len > 0 { data[0] } else { zero };
    if sendto(u.fd, p, data.len as u64, 0, sa[0], sa.len as u32) < 0 {
        if errno_now() == EAGAIN { return Err.TimedOut; }
        return syserr("sendto");
    }
    return Err.None;
}

// Rejoindre un groupe multicast. Sans iface explicite, le noyau choisit
// l'interface par défaut — souvent le mauvais choix en machine virtuelle,
// où le bouclage local veut la loopback en toutes lettres.
fn join(u: Udp&, group: Addr, iface: Addr = Addr { .. }) -> Err {
    if group.family == AF_INET6 { return mcast6_op(u, group, IPV6_JOIN_GROUP, 0); }
    if group.family != AF_INET { return Err.BadAddr; }
    var buf: u8[8] = [0; 8];
    buf[..4].move_from(group.bytes[..4]);
    buf[4..8].move_from(iface.bytes[..4]);
    if setsockopt_raw(u.fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, buf[0], 8) != 0 { return syserr("sockopt"); }
    return Err.None;
}

// Le même, quand on veut nommer l'interface IPv6 par son index.
fn join6_on(u: Udp&, group: Addr, ifindex: i64) -> Err {
    if group.family != AF_INET6 { return Err.BadAddr; }
    return mcast6_op(u, group, IPV6_JOIN_GROUP, ifindex);
}

fn leave(u: Udp&, group: Addr, iface: Addr = Addr { .. }) -> Err {
    if group.family == AF_INET6 { return mcast6_op(u, group, IPV6_LEAVE_GROUP, 0); }
    if group.family != AF_INET { return Err.BadAddr; }
    var buf: u8[8] = [0; 8];
    buf[..4].move_from(group.bytes[..4]);
    buf[4..8].move_from(iface.bytes[..4]);
    if setsockopt_raw(u.fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, buf[0], 8) != 0 { return syserr("sockopt"); }
    return Err.None;
}

// v4 : ip_mreq { groupe, interface } sur 8 octets ; v6 : ipv6_mreq
// { groupe, index } sur 20.
fn mcast6_op(u: Udp&, group: Addr, op: i32, ifindex: i64) -> Err {
    var buf: u8[20] = [0; 20];
    buf[..16].move_from(group.bytes[..16]);
    var ib = bytes_of_u32(ifindex as u32);
    buf[16..20].move_from(ib[..]);
    if setsockopt_raw(u.fd, IPPROTO_IPV6, op, buf[0], 20) != 0 { return syserr("sockopt"); }
    return Err.None;
}

// L'interface de sortie du multicast : par adresse en v4, par index en v6.
fn set_iface(u: Udp&, ip: Addr) -> Err {
    var buf: u8[8] = [0; 8];
    buf[..4].move_from(ip.bytes[..4]);
    if setsockopt_raw(u.fd, IPPROTO_IP, IP_MULTICAST_IF, buf[0], 4) != 0 { return syserr("sockopt"); }
    return Err.None;
}

fn set_iface6(u: Udp&, ifindex: i64) -> Err {
    var idx: i32 = ifindex as i32;
    if setsockopt(u.fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, idx, 4) != 0 { return syserr("sockopt"); }
    return Err.None;
}

fn bytes_of_u32(v: u32) -> u8[4] {
    var b: u8[4] = [0; 4];
    b[0] = v as u8;
    b[1] = (v >> 8) as u8;
    b[2] = (v >> 16) as u8;
    b[3] = (v >> 24) as u8;
    return b;
}

// La portée des datagrammes émis : 1 reste dans le lien local, et le
// multicast en a besoin pour sortir de la machine.
fn set_ttl(u: Udp&, hops: i32) -> Err {
    if u.family == AF_INET6 {
        if setsockopt(u.fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, hops, 4) != 0 { return syserr("sockopt"); }
        return Err.None;
    }
    if setsockopt(u.fd, IPPROTO_IP, IP_MULTICAST_TTL, hops, 4) != 0 { return syserr("sockopt"); }
    return Err.None;
}

// Se réentendre sur le groupe : utile en test, à couper en production.
fn set_loop(u: Udp&, on: bool) -> Err {
    let v: i32 = if on { 1 } else { 0 };
    if u.family == AF_INET6 {
        if setsockopt(u.fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, v, 4) != 0 { return syserr("sockopt"); }
        return Err.None;
    }
    if setsockopt(u.fd, IPPROTO_IP, IP_MULTICAST_LOOP, v, 4) != 0 { return syserr("sockopt"); }
    return Err.None;
}

fn close(u: Udp&) {
    if u.fd >= 0 {
        close(u.fd);
        u.fd = -1;
    }
}

fn peer(u: Udp&, out: u8[>..]&) {
    format(out, Addr { family: u.family, port: u.port, bytes: u.addr });
}
fn peer(u: Udp&) -> u8[>..] {
    var out: u8[>..] = [];
    peer(u, out);
    return out;
}

fn set_timeout(u: Udp&, secs: f64) { u.toms = timeout_ms(secs); }
