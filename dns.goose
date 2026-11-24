// La résolution et le dial. getaddrinfo fait le travail lourd, derrière un
// cache par processus ; le dial TCP lance tous les candidats en parallèle
// avec le départ décalé de la RFC 8305 — un seul poll les surveille, pas
// un thread.
namespace net;
import std;
import os;
import ffi;
import binary;
import platform;
import libc;
import addr;
import dictionary;

// Le cache de résolution, pour la vie du programme : les noms sont copiés
// dans dns_names (jamais raccourci, donc les vues des clés tiennent), les
// adresses aplaties dans dns_addrs, et dns_spans aligne les deux par
// groupes de quatre (début du nom, longueur, début des adresses, nombre).
var dns_names: u8[>..]   = [];
var dns_spans: i64[>..]  = [];
var dns_addrs: Addr[>..] = [];
var dns_index = dictionary<const u8[:], i32> {};

fn cache_get(host: const u8[:], port: i64, out: Addr[>..]&) -> bool {
    let idx = dns_index.get(host);
    guard idx else { return false; }
    let s0 = dns_spans[idx * 4 + 2];
    let cnt = dns_spans[idx * 4 + 3];
    for k in cnt {
        var b = dns_addrs[s0 + k];
        b.port = port as u16;
        out.push(b);
    }
    return true;
}

fn cache_put(host: const u8[:], got: Addr[>..]&) {
    let ns = dns_names.len;
    dns_names.append(host);
    let a0 = dns_addrs.len;
    for a in got {
        var b = a;
        b.port = 0;
        dns_addrs.push(b);
    }
    dns_spans.push(ns);
    dns_spans.push(host.len);
    dns_spans.push(a0);
    dns_spans.push(got.len);
    dns_index.update(dns_names[ns..], 0) { it = (dns_spans.len / 4 - 1) as i32; };
}

// Les adresses qu'un nom désigne, dans l'ordre du résolveur, poussées
// dans out. Le premier passage pour un nom va jusqu'à getaddrinfo — qui
// rend une liste chaînée de structs à champs pointeurs que l'FFI refuse
// de traverser : chaque nœud de 48 octets est relu via ffi::bytes, et son
// sockaddr avec. Le port arrive avec, via le service numérique qu'on lui
// passe. La résolution elle-même reste bloquante ; le cache évite de
// repayer les suivantes.
fn resolve(host: const u8[:], port: i64, out: Addr[>..]&, stype: i32 = SOCK_STREAM) -> Err {
    if cache_get(host, port, out) { return Err.None; }
    var hz: u8[>..] = [];
    hz.append(host);
    hz.push(0);                          // getaddrinfo veut du NUL-terminal
    var svz: u8[>..] = [];
    format(svz, port);
    svz.push(0);
    // struct addrinfo à la main, 48 octets, dans l'ordre des champs C
    var hint: u8[>..] = [];
    binary::write_u32le(hint, 0);                // ai_flags
    binary::write_u32le(hint, 0);                // ai_family = AF_UNSPEC
    binary::write_u32le(hint, stype as u32);     // ai_socktype
    binary::write_u32le(hint, 0);                // ai_protocol
    binary::write_u32le(hint, 0);                // ai_addrlen
    binary::write_u32le(hint, 0);                // le bourrage avant les pointeurs
    binary::write_u64le(hint, 0);                // ai_addr
    binary::write_u64le(hint, 0);                // ai_canonname
    binary::write_u64le(hint, 0);                // ai_next
    var slot: u8[8] = [0; 8];                    // reçoit le pointeur de tête
    let rc = getaddrinfo(hz[0], svz[0], hint[0], slot[0]);
    if rc != 0 { return Err.Name { code: rc }; }
    let head, hok = binary::read_u64le(slot[..], 0);
    if !hok { return Err.Name { code: 0 }; }
    var node = head;
    while node != 0 {
        var raw: u8[>..] = [];
        if !ffi::bytes(node, 48, raw) { break; }
        let fam, ok1 = binary::read_u32le(raw[..], 4);
        let addrlen, ok2 = binary::read_u32le(raw[..], 16);
        let addrp, ok3 = binary::read_u64le(raw[..], 24);
        let next, ok4 = binary::read_u64le(raw[..], 40);
        if !ok1 || !ok2 || !ok3 || !ok4 { break; }
        let fami = fam as i32;
        let need = if fami == AF_INET { 16 } else { 28 };
        if (fami == AF_INET || fami == AF_INET6) && addrp != 0 && addrlen >= need {
            var sab: u8[>..] = [];
            if ffi::bytes(addrp, addrlen, sab) {
                var a = Addr { family: fami };
                a.port = binary::read_u16be(sab[..], 2);
                if fami == AF_INET { a.bytes[..4].move_from(sab[4..8]); }
                if fami == AF_INET6 { a.bytes[..16].move_from(sab[8..24]); }
                out.push(a);
            }
        }
        node = next;
    }
    freeaddrinfo(head);
    if out.len > 0 { cache_put(host, out); }
    return Err.None;
}

// Une socket + son connect. in_flight dit si connect a répondu
// EINPROGRESS : le fd vit, et le poll dira la suite.
fn launch(a: Addr, stype: i32) -> i32, bool, Err {
    let fd, oerr = sock_open(a.family, stype);
    if oerr != Err.None { return -1, false, oerr; }
    var sa: u8[>..] = [];
    sockaddr(a, sa);
    if connect(fd, sa[0], sa.len as u32) == 0 { return fd, false, Err.None; }
    let e = errno_now();
    if e != EINPROGRESS {
        close(fd);
        return -1, false, Err.Sys { op: "connect", code: e };
    }
    return fd, true, Err.None;
}

// Le squelette commun de connect et udp_dial : le résolveur d'abord, puis
// le parcours séquentiel pour UDP (connect n'y bloque jamais) ou le
// parallèle échelonné pour TCP.
fn dial(host: const u8[:], port: i64, dgram: bool, secs: f64) -> i32, Addr, Err {
    var a = Addr { .. };
    if port < 0 || port > 65535 { return -1, a, Err.BadPort; }
    let stype: i32 = if dgram { SOCK_DGRAM } else { SOCK_STREAM };
    var cands: Addr[>..] = [];
    let parsed, perr = parse_addr(host);
    if perr == Err.None {
        parsed.port = port as u16;
        cands.push(parsed);
    } else {
        let rerr = resolve(host, port, cands, stype);
        if rerr != Err.None { return -1, a, rerr; }
    }
    if cands.len == 0 { return -1, a, Err.BadAddr; }
    let toms = timeout_ms(secs);
    if dgram { return dial_seq(cands, stype); }
    return dial_parallel(cands, toms);
}

fn dial_seq(cands: Addr[>..]&, stype: i32) -> i32, Addr, Err {
    var last = Err.BadAddr;
    for c in cands {
        let fd, inflight, err = launch(c, stype);
        if err == Err.None { return fd, c, Err.None; }
        last = err;
    }
    return -1, Addr { .. }, last;
}

// Tous les candidats finissent lancés, échelonnés de 250 ms pour laisser
// sa chance à la première famille ; le premier qui sort de poll sans
// erreur gagne, et tous les autres fds sont refermés. Un timeout rend
// TimedOut une fois l'échéance passée, tout le vol compris.
fn dial_parallel(cands: Addr[>..]&, toms: i32) -> i32, Addr, Err {
    var work: Addr[>..]   = [];          // aligné sur pfds
    var pfds: PollFd[>..] = [];
    var started = 0;
    var last = Err.BadAddr;
    let start = clock_ns();
    let deadline: i64 = if toms < 0 { -1 } else { start + toms as i64 * 1000000 };
    loop {
        let now = clock_ns();
        while started < cands.len && now - start >= started * STAGGER_NS {
            let fd, inflight, err = launch(cands[started], SOCK_STREAM);
            if err == Err.None && !inflight {
                // boucle locale : connect a fini tout de suite
                close_flight(pfds);
                return fd, cands[started], Err.None;
            }
            if err == Err.None {
                pfds.push(PollFd { fd: fd, events: POLLOUT });
                work.push(cands[started]);
            } else {
                last = err;
            }
            started++;
        }
        if pfds.len == 0 && started == cands.len {
            return -1, Addr { .. }, last;
        }
        poll(pfds[0], pfds.len as u64, next_ms(start, deadline, started, cands.len, clock_ns()));
        var i = 0;
        while i < pfds.len {
            if pfds[i].revents != 0 {
                var soerr: i32 = 0;
                var solen: u32 = 4;
                getsockopt(pfds[i].fd, SOL_SOCKET, SO_ERROR, soerr, solen);
                if soerr == 0 {
                    let wfd = pfds[i].fd;
                    let waddr = work[i];
                    drop_at(pfds, work, i);
                    close_flight(pfds);
                    return wfd, waddr, Err.None;
                }
                last = Err.Sys { op: "connect", code: soerr };
                close(pfds[i].fd);
                drop_at(pfds, work, i);
                continue;
            }
            i++;
        }
        if deadline >= 0 && clock_ns() >= deadline {
            close_flight(pfds);
            return -1, Addr { .. }, Err.TimedOut;
        }
    }
}

// referme tout un vol de fd en attente
fn close_flight(pfds: PollFd[>..]&) {
    for p in pfds { close(p.fd); }
    pfds.clear();
}

fn drop_at(pfds: PollFd[>..]&, work: Addr[>..]&, i: i64) {
    let last = pfds.len - 1;
    pfds[i] = pfds[last];
    work[i] = work[last];
    pfds.pop();
    work.pop();
}

// Le temps jusqu'au prochain événement : une mise en route décalée ou
// l'échéance globale. -1 dit à poll d'attendre indéfiniment.
fn next_ms(start: i64, deadline: i64, started: i64, total: i64, now: i64) -> i32 {
    var ns: i64 = -1;
    if started < total { ns = start + started * STAGGER_NS - now; }
    if deadline >= 0 && (ns < 0 || deadline - now < ns) { ns = deadline - now; }
    if ns < 0 { return -1; }
    if ns <= 0 { return 0; }
    (ns / 1000000) as i32 + 1
}
