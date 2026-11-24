// Serveur echo : ce qu'on envoie revient, jusqu'à la déconnexion.
//
//   goose run examples/echo_server.goose
//
// puis depuis un autre terminal (ou `goose run examples/echo_client.goose`) :
//
//   nc 127.0.0.1 8080
//
// "::" écoute en IPv6 et, V6ONLY forcé à 0, accepte aussi l'IPv4. Si votre
// boîte n'a pas d'IPv6, passez 0.0.0.0 en argument.
import net from "..";
import os;

fn main() {
    let args = args();
    let at = if args.len > 1 { args[1] } else { "::" };
    let l, err = net::listen(at, 8080);
    if err != net::Err.None { print("listen: ", err); return; }
    defer l.close();
    print("echo on ", at, ":8080, ctrl-c pour arrêter");

    let why = l.accept_loop() { conn =>
        print("conn from ", conn.peer());
        loop {
            let buf, err = conn.read();
            if err == net::Err.Closed { break; }
            if err != net::Err.None { print("read: ", err); break; }
            let _, werr = conn.write(buf);
            if werr != net::Err.None { print("write: ", werr); break; }
        }
    };
    if why != net::Err.None { print("accept loop ended: ", why); }
}
