// Personne n'envoie rien ; le read rend net::Err.TimedOut au bout de
// 200 ms. Port 0 : l'OS choisit, on n'en a pas besoin pour rien recevoir.
//
//   goose run examples/timeout.goose
import net from "..";
import os;

fn main() {
    let u, err = net::udp_bind("127.0.0.1", 0);
    if err != net::Err.None { print("bind: ", err); return; }
    defer u.close();

    u.set_timeout(0.2);
    let t0 = clock();
    let _, rerr = u.read();
    let dt = clock() - t0;

    if rerr == net::Err.TimedOut {
        print("timed out après ", dt, " s, comme prévu");
        return;
    }
    print("read: ", rerr, " — pas ce qu'on attendait");
}
