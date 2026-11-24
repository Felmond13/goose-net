// Sockets TCP, UDP et Unix pour Goose — et pas une ligne de C : les
// appels POSIX sont déclarés dans le bloc extern "libc" (libc.goose),
// liés par le loader au démarrage, et net.build mappe le nom de la
// bibliothèque par plateforme.
//
// Sous le capot tout est non-bloquant (SOCK_NONBLOCK dès socket()) et
// chaque opération passe par poll : un seul mécanisme donne des timeouts
// sur read/write/accept/connect, sans timeval dont le layout change d'OS
// à l'OS, et sans fcntl qui est variadic donc inbindable.
//
// Le paquet se découpe par famille : tcp.goose, udp.goose (avec le
// multicast), unix.goose, dns.goose (résolution, cache, RFC 8305),
// addr.goose, libc.goose, platform.goose, et crypto/ + tls.goose pour le
// TLS. `goose run net.goose` fait tourner le test de bout en bout.
namespace net;
import std;
import os;
import platform;
import libc;
import addr;
import dns;
import tcp;
import udp;
import unix;
import crypto.hash;
import crypto.aes;
import crypto.big;
import crypto.x25519;
import crypto.p256;
import tls;

// Traîne derrière tout appel qui peut échouer. Sys nomme l'appel POSIX et
// porte l'errno brut ; Name porte le code de getaddrinfo, qui n'est pas
// un errno ; Tls porte le texte rendu au moment de l'échec, puisque le
// rendu des erreurs TLS ne doit pas dépendre du crypto au moment du
// print. Le hook format plus bas rend tout ça lisible.
enum Err {
    None,
    BadAddr,
    BadPort,
    Closed,
    TimedOut,
    Name { code: i32 },
    Sys { op: const u8[:], code: i32 },
    Tls { text: const u8[:] },
}

fn format(out: u8[>..]&, e: Err) {
    match e {
        None => format(out, "no error"),
        BadAddr => format(out, "bad address"),
        BadPort => format(out, "port out of range"),
        Closed => format(out, "closed by peer"),
        TimedOut => format(out, "timed out"),
        Name n => {
            format(out, "resolve failed");
            // le tampon de gai_strerror appartient à libc ; copié aussitôt
            let p = gai_strerror(n.code);
            if p != 0 {
                var msg: u8[>..] = [];
                if ffi::cstr(p, msg) { format(out, ": ", msg); }
            }
        },
        Tls t => format(out, "tls: ", t.text),
        Sys s => {
            format(out, s.op, " failed");
            let p = strerror(s.code);
            if p != 0 {
                var msg: u8[>..] = [];
                if ffi::cstr(p, msg) { format(out, ": ", msg); }
            }
            format(out, " (errno ", s.code, ")");
        },
    }
}

// Le test de bout en bout : TCP v4 via le résolveur, TCP v6, UDP dans les
// deux sens, Unix stream et datagram, multicast en boucle locale, un
// timeout qui doit dire TimedOut, et une résolution qui repasse par le
// cache. Le noyau termine un connect contre la backlog avant que
// quiconque accepte, donc tout tient dans un seul processus, sans
// threads.
fn smoke() {
    let l, lerr = listen("127.0.0.1", 46913);
    if lerr != Err.None { print("listen: ", lerr); return; }
    let c, cerr = connect("localhost", 46913);
    if cerr != Err.None { print("connect: ", cerr); return; }
    let s, aerr = accept(l);
    if aerr != Err.None { print("accept: ", aerr); return; }
    print("tcp peer is ", s.peer());

    let _, w1 = c.write("hello, goose");
    if w1 != Err.None { print("client write: ", w1); return; }
    let got, rerr = s.read();
    if rerr != Err.None { print("server read: ", rerr); return; }
    if got != "hello, goose" { print("echoed ", got, ", not what was sent"); return; }
    let _, w2 = s.write("well hello");
    if w2 != Err.None { print("server write: ", w2); return; }
    let back, berr = c.read();
    if berr != Err.None { print("client read: ", berr); return; }
    print("tcp round trip: ", back);
    c.close();
    s.close();
    l.close();

    let l6, l6err = listen("::1", 46914);
    if l6err != Err.None { print("listen v6: ", l6err); return; }
    let c6, c6err = connect("::1", 46914);
    if c6err != Err.None { print("connect v6: ", c6err); return; }
    let s6, a6err = accept(l6);
    if a6err != Err.None { print("accept v6: ", a6err); return; }
    print("v6 peer is ", s6.peer());
    let _, w3 = c6.write("hello, six");
    if w3 != Err.None { print("v6 write: ", w3); return; }
    let got6, r6err = s6.read();
    if r6err != Err.None { print("v6 read: ", r6err); return; }
    if got6 != "hello, six" { print("v6 echoed ", got6); return; }
    print("tcp v6 ok");
    c6.close();
    s6.close();
    l6.close();

    let us, uberr = udp_bind("127.0.0.1", 46915);
    if uberr != Err.None { print("udp_bind: ", uberr); return; }
    let uc, uderr = udp_dial("127.0.0.1", 46915);
    if uderr != Err.None { print("udp_dial: ", uderr); return; }
    if uc.write("ping over udp") != Err.None { print("udp write failed"); return; }
    let dg, from, frerr = us.read_from();
    if frerr != Err.None { print("read_from: ", frerr); return; }
    if dg != "ping over udp" { print("udp got ", dg); return; }
    if us.write_to("pong", from) != Err.None { print("write_to failed"); return; }
    let dback, derr = uc.read();
    if derr != Err.None { print("udp read: ", derr); return; }
    print("udp round trip: ", dback, " from ", from);
    uc.close();
    us.close();

    // unix stream : même Listener/Conn que TCP, un chemin à la place
    let ul, ulerr = unix_listen("/tmp/goose-net-smoke.sock");
    if ulerr != Err.None { print("unix_listen: ", ulerr); return; }
    let ucx, ucerr = unix_connect("/tmp/goose-net-smoke.sock");
    if ucerr != Err.None { print("unix_connect: ", ucerr); return; }
    let usx, uaerr = accept(ul);
    if uaerr != Err.None { print("unix accept: ", uaerr); return; }
    let _, uw = ucx.write("over the socket file");
    if uw != Err.None { print("unix write: ", uw); return; }
    let ugot, urerr = usx.read();
    if urerr != Err.None { print("unix read: ", urerr); return; }
    if ugot != "over the socket file" { print("unix echoed ", ugot); return; }
    print("unix stream ok");
    ucx.close();
    usx.close();
    ul.close();

    // unix datagram : les deux côtés sont liés (la convention unix), le
    // client écrit à l'adresse du serveur, qui répond au chemin que
    // read_from lui a rendu
    let ud_srv, uderr1 = unix_dgram("/tmp/goose-net-smoke.dgram");
    if uderr1 != Err.None { print("unix_dgram bind: ", uderr1); return; }
    let ud_cli, uderr2 = unix_dgram("/tmp/goose-net-smoke.cli");
    if uderr2 != Err.None { print("unix_dgram cli: ", uderr2); return; }
    if unix_send_to(ud_cli, "dgram hello", "/tmp/goose-net-smoke.dgram") != Err.None {
        print("unix send_to failed");
        return;
    }
    let udg, usender, ufrerr = ud_srv.read_from();
    if ufrerr != Err.None { print("unix read_from: ", ufrerr); return; }
    if udg != "dgram hello" { print("unix dgram got ", udg); return; }
    if unix_send_to(ud_srv, "dgram pong", usender) != Err.None { print("unix reply failed"); return; }
    let udback, uderr3 = ud_cli.read();
    if uderr3 != Err.None { print("unix dgram read: ", uderr3); return; }
    print("unix dgram round trip: ", udback);
    ud_cli.close();
    ud_srv.close();

    // multicast v4 : on rejoint le groupe sur la boucle en toutes
    // lettres — en machine virtuelle, l'interface par défaut ne rapporte
    // rien — puis on s'envoie un datagramme que la boucle locale ramène
    let lo, loerr = parse_addr("127.0.0.1");
    if loerr != Err.None { print("mcast lo: ", loerr); return; }
    let m, merr = udp_bind("0.0.0.0", 0);
    if merr != Err.None { print("mcast bind: ", merr); return; }
    let grp, ggerr = addr("224.0.0.251", 0);
    if ggerr != Err.None { print("mcast addr: ", ggerr); return; }
    let joined = join(m, grp, lo);
    if joined != Err.None { print("mcast join: ", joined); return; }
    m.set_timeout(2.0);
    let dst = grp;
    dst.port = m.port;
    let ms, mserr = udp_dial("127.0.0.1", 0);
    if mserr != Err.None { print("mcast dial: ", mserr); return; }
    if ms.set_iface(lo) != Err.None { print("mcast iface failed"); return; }
    if ms.set_ttl(1) != Err.None { print("mcast ttl failed"); return; }
    if ms.write_to("hello multicast", dst) != Err.None { print("mcast send failed"); return; }
    let md, mfrom, mfrerr = m.read_from();
    if mfrerr != Err.None { print("mcast read: ", mfrerr); return; }
    if md != "hello multicast" { print("mcast got ", md); return; }
    print("multicast loop ok");
    ms.close();
    if leave(m, grp, lo) != Err.None { print("mcast leave failed"); return; }
    m.close();

    // un timeout qui ne doit rien attendre du tout
    let ut, uterr = udp_bind("127.0.0.1", 0);
    if uterr != Err.None { print("udp_bind 2: ", uterr); return; }
    ut.set_timeout(0.05);
    let _, terr = ut.read();
    if terr == Err.TimedOut { print("timeout ok"); } else { print("timeout miss: ", terr); }
    ut.close();

    print("smoke test ok");
}

fn ::main() { net::smoke(); }
