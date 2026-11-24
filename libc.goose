// La plomberie syscall : le bloc extern "libc", errno, et poll. Rien ici
// ne connaît TCP, UDP ou autre — c'est la porte vers l'OS, c'est tout.
namespace net;
import std;
import ffi;         // errno et les pointeurs C repassent par là : un extern ne peut pas rendre de référence
import binary;
import platform;

// Déclarées une fois pour tout le paquet. Aucun C écrit : ce sont les
// fonctions que tout système POSIX embarque déjà.
extern "libc" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn setsockopt(fd: i32, level: i32, name: i32, value: const i32&, len: u32) -> i32;
    fn setsockopt_raw(fd: i32, level: i32, name: i32, value: const u8&, len: u32) -> i32 = "setsockopt";
    fn getsockopt(fd: i32, level: i32, name: i32, value: i32&, len: u32&) -> i32;
    fn bind(fd: i32, addr: const u8&, len: u32) -> i32;
    fn listen(fd: i32, backlog: i32) -> i32;
    fn accept(fd: i32, addr: u8&, len: u32&) -> i32;
    fn connect(fd: i32, addr: const u8&, len: u32) -> i32;
    fn getsockname(fd: i32, addr: u8&, len: u32&) -> i32;
    fn recv(fd: i32, buf: u8&, len: u64, flags: i32) -> i64;
    fn send(fd: i32, buf: const u8&, len: u64, flags: i32) -> i64;
    fn recvfrom(fd: i32, buf: u8&, len: u64, flags: i32, addr: u8&, alen: u32&) -> i64;
    fn sendto(fd: i32, buf: const u8&, len: u64, flags: i32, addr: const u8&, alen: u32) -> i64;
    fn poll(fds: PollFd&, nfds: u64, timeout: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn signal(sig: i32, handler: u64) -> u64;
    fn uname(buf: u8&) -> i32;
    fn inet_pton(af: i32, src: const u8&, dst: u8&) -> i32;
    fn inet_ntop(af: i32, src: const u8&, dst: u8&, size: u32) -> u64;
    fn getaddrinfo(node: const u8&, service: const u8&, hints: const u8&, res: u8&) -> i32;
    fn freeaddrinfo(res: u64);
    fn gai_strerror(code: i32) -> u64;
    fn strerror(code: i32) -> u64;
    fn __errno_location() -> u64;
    // le hasard du systeme passe par /dev/urandom ; read est aliase pour
    // ne pas heurter le read() des connexions
    fn sys_open(path: const u8&, flags: i32) -> i32 = "open";
    fn sys_read(fd: i32, buf: u8&, len: u64) -> i64 = "read";
}

// struct pollfd, 8 octets, tel que C le veut.
struct PollFd { fd: i32, events: i16, revents: i16 = 0 }

// errno est thread-local ; __errno_location rend son adresse et un extern
// n'a pas le droit de rendre une référence, donc les quatre octets passent
// par ffi::bytes. Chemins d'erreur seulement, le détour ne se voit jamais
// sur le chemin courant.
fn errno_now() -> i32 {
    var raw: u8[>..] = [];
    ffi::bytes(__errno_location(), 4, raw);
    let code, ok = binary::read_i32le(raw[..], 0);
    if !ok { return 0; }
    code
}

fn syserr(op: const u8[:]) -> Err {
    Err.Sys { op: op, code: errno_now() }
}

// Une attente de readiness, le seul mouvement d'IO de toute la lib : rend
// 1 quand le fd est prêt, 0 au temps écoulé, -1 sur erreur. ms négatif
// attend indéfiniment, comme poll veut.
fn wait_ready(fd: i32, events: i16, ms: i32) -> i32 {
    var p = PollFd { fd: fd, events: events };
    poll(p, 1, ms)
}

fn timeout_ms(secs: f64) -> i32 {
    if secs <= 0 { return -1; }
    let ms = secs * 1000.0;
    if ms > 2147483647.0 { return 2147483647; }
    ms as i32
}

// connect non-bloquant pour une socket déjà en place : EINPROGRESS, poll,
// puis SO_ERROR. C'est le seul moyen d'avoir un timeout sur connect, et
// tout le monde passe ici (TCP, UDP, Unix).
fn sock_connect(fd: i32, sa: const u8[:], toms: i32) -> Err {
    if connect(fd, sa[0], sa.len as u32) == 0 { return Err.None; }
    if errno_now() != EINPROGRESS { return syserr("connect"); }
    let r = wait_ready(fd, POLLOUT, toms);
    if r == 0 { return Err.TimedOut; }
    if r < 0 { return syserr("poll"); }
    var soerr: i32 = 0;
    var solen: u32 = 4;
    if getsockopt(fd, SOL_SOCKET, SO_ERROR, soerr, solen) != 0 { return syserr("sockopt"); }
    if soerr != 0 { return Err.Sys { op: "connect", code: soerr }; }
    return Err.None;
}

// La socket non-bloquante qu'on utilise partout, au type près.
fn sock_open(family: i32, stype: i32) -> i32, Err {
    let fd = socket(family, stype | SOCK_NONBLOCK, 0);
    if fd < 0 { return -1, syserr("socket"); }
    return fd, Err.None;
}
