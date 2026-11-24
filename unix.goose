// Sockets du domaine Unix, stream et datagram. Pas d'adresse réseau : un
// chemin dans le système de fichiers, borné à 104 octets, le max commun
// à Linux (108) et Darwin (104). Les connexions stream réutilisent les
// types Listener/Conn de TCP, qui sont familiers de la famille.
namespace net;
import std;
import os;           // pour reprendre le socle du listener au restart
import binary;
import platform;
import libc;

let UNIX_PATH_MAX = 104;
let UNXMAX = 212992;     // le max d'un datagramme unix par défaut (SO_SNDBUF)

fn unix_sockaddr(path: const u8[:], out: u8[>..]&) -> Err {
    out.clear();
    if path.len >= UNIX_PATH_MAX { return Err.BadAddr; }
    if OS_DARWIN {
        out.push((path.len + 3) as u8);      // sun_len : 1 + 1 + chemin + NUL
        out.push(AF_UNIX);             // sun_family
    } else {
        binary::write_u16le(out, AF_UNIX);
    }
    out.append(path);
    out.push(0);
    return Err.None;
}

// Le fichier existant est supprimé : unix_listen reprend son socle au
// restart, comme le font tous les serveurs Unix.
fn unix_listen(path: const u8[:]) -> Listener, Err {
    delete_file(path);
    let fd, oerr = sock_open(AF_UNIX, SOCK_STREAM);
    if oerr != Err.None { return Listener { fd: -1 }, oerr; }
    var sa: u8[>..] = [];
    let serr = unix_sockaddr(path, sa);
    guard serr == Err.None else {
        close(fd);
        return Listener { fd: -1 }, serr;
    }
    if bind(fd, sa[0], sa.len as u32) != 0 {
        let e = syserr("bind");
        close(fd);
        return Listener { fd: -1 }, e;
    }
    if listen(fd, 16) != 0 {
        let e = syserr("listen");
        close(fd);
        return Listener { fd: -1 }, e;
    }
    return Listener { fd: fd, family: AF_UNIX }, Err.None;
}

fn unix_connect(path: const u8[:], secs: f64 = 0) -> Conn, Err {
    let fd, oerr = sock_open(AF_UNIX, SOCK_STREAM);
    if oerr != Err.None { return Conn { fd: -1, .. }, oerr; }
    var sa: u8[>..] = [];
    let serr = unix_sockaddr(path, sa);
    guard serr == Err.None else {
        close(fd);
        return Conn { fd: -1, .. }, serr;
    }
    let cerr = sock_connect(fd, sa[..], timeout_ms(secs));
    if cerr != Err.None {
        close(fd);
        return Conn { fd: -1, .. }, cerr;
    }
    return Conn { fd: fd, family: AF_UNIX, .. }, Err.None;
}

// Une socket de datagramme Unix, liée au chemin s'il y en a un ; "" laisse
// le noyau choisir, c'est le cas du client qui parle en send_to ou qui se
// connecte à un peer fixe.
fn unix_dgram(path: const u8[:]) -> Dgram, Err {
    let fd, oerr = sock_open(AF_UNIX, SOCK_DGRAM);
    if oerr != Err.None { return Dgram { fd: -1, .. }, oerr; }
    if path.len > 0 {
        if path.len >= UNIX_PATH_MAX {
            close(fd);
            return Dgram { fd: -1, .. }, Err.BadAddr;
        }
        delete_file(path);
        var sa: u8[>..] = [];
        let serr = unix_sockaddr(path, sa);
        guard serr == Err.None else {
            close(fd);
            return Dgram { fd: -1, .. }, serr;
        }
        if bind(fd, sa[0], sa.len as u32) != 0 {
            let e = syserr("bind");
            close(fd);
            return Dgram { fd: -1, .. }, e;
        }
    }
    return Dgram { fd: fd, .. }, Err.None;
}

// Fixe le peer, après quoi write parle à lui seul.
fn unix_dgram_connect(d: Dgram&, path: const u8[:]) -> Err {
    var sa: u8[>..] = [];
    let serr = unix_sockaddr(path, sa);
    guard serr == Err.None else { return serr; }
    if connect(d.fd, sa[0], sa.len as u32) != 0 { return syserr("connect"); }
    return Err.None;
}

fn unix_send_to(d: Dgram&, data: const u8[:], path: const u8[:]) -> Err {
    let r = wait_ready(d.fd, POLLOUT, d.toms);
    if r == 0 { return Err.TimedOut; }
    if r < 0 { return syserr("poll"); }
    var sa: u8[>..] = [];
    let serr = unix_sockaddr(path, sa);
    guard serr == Err.None else { return serr; }
    var zero: u8 = 0;
    let p: const u8& = if data.len > 0 { data[0] } else { zero };
    if sendto(d.fd, p, data.len as u64, 0, sa[0], sa.len as u32) < 0 {
        if errno_now() == EAGAIN { return Err.TimedOut; }
        return syserr("sendto");
    }
    return Err.None;
}

// Le datagramme reçu. Le 0 d'Unix est un datagramme vide, pas une fermeture.
fn read(d: Dgram&) -> const u8[:], Err {
    let r = wait_ready(d.fd, POLLIN, d.toms);
    if r == 0 { d.rbuf.clear(); return d.rbuf[..], Err.TimedOut; }
    if r < 0 { d.rbuf.clear(); return d.rbuf[..], syserr("poll"); }
    d.rbuf.clear();
    d.rbuf.resize(UNXMAX, 0);
    let n = recv(d.fd, d.rbuf[0], UNXMAX, 0);
    if n < 0 {
        d.rbuf.clear();
        if errno_now() == EAGAIN { return d.rbuf[..], Err.TimedOut; }
        return d.rbuf[..], syserr("recv");
    }
    d.rbuf.resize(n);
    return d.rbuf[..], Err.None;
}

// Le datagramme reçu, plus le chemin de l'émetteur : la chaîne vide pour
// un client sans chemin (la plupart).
fn read_from(d: Dgram&) -> const u8[:], u8[>..], Err {
    let r = wait_ready(d.fd, POLLIN, d.toms);
    if r == 0 { d.rbuf.clear(); return d.rbuf[..], sun_path_holder(), Err.TimedOut; }
    if r < 0 { d.rbuf.clear(); return d.rbuf[..], sun_path_holder(), syserr("poll"); }
    d.rbuf.clear();
    d.rbuf.resize(UNXMAX, 0);
    var sa:    u8[112] = [0; 112];
    var salen: u32     = 112;
    let n = recvfrom(d.fd, d.rbuf[0], UNXMAX, 0, sa[0], salen);
    if n < 0 {
        d.rbuf.clear();
        let e = if errno_now() == EAGAIN { Err.TimedOut } else { syserr("recvfrom") };
        return d.rbuf[..], sun_path_holder(), e;
    }
    d.rbuf.resize(n);
    return d.rbuf[..], sun_path(sa[..]), Err.None;
}

// send peut n'avaler qu'une partie d'un flux, mais un datagramme part
// entier : un seul appel, et il faut un peer fixé (unix_dgram_connect).
fn write(d: Dgram&, data: const u8[:]) -> Err {
    let r = wait_ready(d.fd, POLLOUT, d.toms);
    if r == 0 { return Err.TimedOut; }
    if r < 0 { return syserr("poll"); }
    var zero: u8 = 0;
    let p: const u8& = if data.len > 0 { data[0] } else { zero };
    if send(d.fd, p, data.len as u64, 0) < 0 {
        if errno_now() == EAGAIN { return Err.TimedOut; }
        return syserr("send");
    }
    return Err.None;
}

fn close(d: Dgram&) {
    if d.fd >= 0 {
        close(d.fd);
        d.fd = -1;
    }
}

fn set_timeout(d: Dgram&, secs: f64) { d.toms = timeout_ms(secs); }

struct Dgram { fd: i32, toms: i32 = -1, rbuf: u8[>..] }

// le chemin du sockaddr qu'un recvfrom vient d'écrire, coupé au NUL
fn sun_path(sa: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let end = find(sa[2..], "\0");
    if end > 0 { out.append(sa[2..2 + end]); }
    return out;
}
fn sun_path_holder() -> u8[>..] {
    var out: u8[>..] = [];
    return out;
}
