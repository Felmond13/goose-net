// TCP : listeners, connexions, read en vue zéro-copie, write qui boucle
// sur send. Les sockets naissent non-bloquantes et chaque opération passe
// d'abord par poll, ce qui donne les timeouts partout.
namespace net;
import std;
import platform;
import libc;
import addr;
import dns;

struct Listener { fd: i32, family: i32 = 0, toms: i32 = -1 }

// Une connexion TCP. read() rend des vues dans rbuf, donc les octets
// restent en place jusqu'à ce que le read suivant réutilise le tampon.
struct Conn { fd: i32, family: i32 = 0, port: u16 = 0, addr: u8[16] = [0; 16], toms: i32 = -1, rbuf: u8[>..] }

fn listen(host: const u8[:], port: i64, reuseport: bool = false) -> Listener, Err {
    var a, aerr = parse_addr(host);
    if aerr != Err.None { return Listener { fd: -1 }, aerr; }
    if port < 0 || port > 65535 { return Listener { fd: -1 }, Err.BadPort; }
    a.port = port as u16;
    // un send sur un peer mort lèverait SIGPIPE et tuerait le programme
    // avant que write() voie une erreur
    signal(SIGPIPE, SIG_IGN);
    let fd, oerr = sock_open(a.family, SOCK_STREAM);
    if oerr != Err.None { return Listener { fd: -1 }, oerr; }
    let one: i32 = 1;
    // SO_REUSEADDR, sinon chaque restart en dev attend la fin du TIME_WAIT
    if setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, one, 4) != 0 {
        let e = syserr("sockopt");
        close(fd);
        return Listener { fd: -1 }, e;
    }
    if reuseport && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, one, 4) != 0 {
        let e = syserr("sockopt");
        close(fd);
        return Listener { fd: -1 }, e;
    }
    if a.family == AF_INET6 {
        // le même dual-stack partout : "::" accepte aussi l'IPv4-mappé.
        // Linux démarre à V6ONLY=0, macOS à 1.
        let off: i32 = 0;
        if setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, off, 4) != 0 {
            let e = syserr("sockopt");
            close(fd);
            return Listener { fd: -1 }, e;
        }
    }
    var sa: u8[>..] = [];
    sockaddr(a, sa);
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
    a.port = bound_port(fd) as u16;
    return Listener { fd: fd, family: a.family }, Err.None;
}

// Bloque jusqu'à l'arrivée d'une connexion, dans la limite du timeout du
// listener, s'il en a un. Marche aussi sur un listener Unix.
fn accept(l: Listener&) -> Conn, Err {
    let r = wait_ready(l.fd, POLLIN, l.toms);
    if r == 0 { return Conn { fd: -1, .. }, Err.TimedOut; }
    if r < 0 { return Conn { fd: -1, .. }, syserr("poll"); }
    var sa:    u8[64] = [0; 64];
    var salen: u32    = 64;
    let fd = accept(l.fd, sa[0], salen);
    if fd < 0 {
        // poll s'est parfois trompé ; EAGAIN derrière une readiness vaut
        // TimedOut, c'est le même mal
        if errno_now() == EAGAIN { return Conn { fd: -1, .. }, Err.TimedOut; }
        return Conn { fd: -1, .. }, syserr("accept");
    }
    let a = sockaddr_addr(sa[..]);
    return Conn { fd: fd, family: a.family, port: a.port, addr: a.bytes, .. }, Err.None;
}

// Appelle F pour chaque connexion jusqu'à ce qu'accept échoue, et referme
// chaque conn une fois F fini avec elle. Rend l'erreur qui a arrêté la
// boucle.
fn accept_loop<F>(l: Listener&) -> Err {
    loop {
        let conn, err = accept(l);
        if err != Err.None { return err; }
        F(conn);
        close(conn);
    }
}

// Ce qui est arrivé cette fois-ci, en vue dans le tampon de la conn : pas
// de copie. Le tampon est réutilisé par le read suivant, et le checker le
// fera savoir si tu tiens encore une vue du précédent.
fn read(conn: Conn&) -> const u8[:], Err {
    let r = wait_ready(conn.fd, POLLIN, conn.toms);
    if r == 0 { conn.rbuf.clear(); return conn.rbuf[..], Err.TimedOut; }
    if r < 0 { conn.rbuf.clear(); return conn.rbuf[..], syserr("poll"); }
    conn.rbuf.clear();
    conn.rbuf.resize(CHUNK, 0);
    let n = recv(conn.fd, conn.rbuf[0], CHUNK, 0);
    if n < 0 {
        conn.rbuf.clear();
        if errno_now() == EAGAIN { return conn.rbuf[..], Err.TimedOut; }
        return conn.rbuf[..], syserr("recv");
    }
    if n == 0 { conn.rbuf.clear(); return conn.rbuf[..], Err.Closed; }
    conn.rbuf.resize(n);
    return conn.rbuf[..], Err.None;
}

// send peut n'avaler qu'une partie du tampon, d'où la boucle ; le compte
// rendu dit ce qui est parti, ce qui compte surtout quand un timeout
// coupe le repas en deux.
fn write(conn: Conn&, data: const u8[:]) -> i64, Err {
    var sent = 0;
    while sent < data.len {
        let r = wait_ready(conn.fd, POLLOUT, conn.toms);
        if r == 0 { return sent, Err.TimedOut; }
        if r < 0 { return sent, syserr("poll"); }
        let n = send(conn.fd, data[sent], (data.len - sent) as u64, 0);
        if n < 0 {
            if errno_now() == EAGAIN { return sent, Err.TimedOut; }
            return sent, syserr("send");
        }
        sent += n;
    }
    return sent, Err.None;
}

// Un littéral IP ou un nom de domaine ; dans le second cas le résolveur
// donne des candidats que le dial essaie en parallèle (RFC 8305). secs
// borne toute l'opération, résolution comprise dans la mesure où poll
// surveille ; 0 attend indéfiniment.
fn connect(host: const u8[:], port: i64, secs: f64 = 0) -> Conn, Err {
    let fd, a, err = dial(host, port, false, secs);
    if err != Err.None { return Conn { fd: -1, .. }, err; }
    return Conn { fd: fd, family: a.family, port: a.port, addr: a.bytes, .. }, Err.None;
}

fn close(conn: Conn&) {
    if conn.fd >= 0 {
        close(conn.fd);
        // un second close tomberait sur le fd que le numéro aura reculé
        conn.fd = -1;
    }
}

fn close(l: Listener&) {
    if l.fd >= 0 {
        close(l.fd);
        l.fd = -1;
    }
}

// Le correspondant sous la forme "1.2.3.4:80" ou "[::1]:80". Sans sens
// sur une connexion Unix, dont les pairs sont anonymes la plupart du temps.
fn peer(conn: Conn&, out: u8[>..]&) {
    format(out, Addr { family: conn.family, port: conn.port, bytes: conn.addr });
}
fn peer(conn: Conn&) -> u8[>..] {
    var out: u8[>..] = [];
    peer(conn, out);
    return out;
}

fn set_timeout(conn: Conn&, secs: f64) { conn.toms = timeout_ms(secs); }
fn set_timeout(l: Listener&, secs: f64) { l.toms = timeout_ms(secs); }
