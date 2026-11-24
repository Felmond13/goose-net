// Un aller-retour UDP complet dans un seul processus : la socket liée
// reçoit le datagramme déjà envoyé par la socket connectée, puis répond à
// l'adresse que read_from a rendue.
//
//   goose run examples/udp_echo.goose
import net from "..";

fn main() {
    let srv, berr = net::udp_bind("127.0.0.1", 8081);
    if berr != net::Err.None { print("udp_bind: ", berr); return; }
    let cli, derr = net::udp_dial("127.0.0.1", 8081);
    if derr != net::Err.None { print("udp_dial: ", derr); return; }
    defer cli.close();
    defer srv.close();

    if cli.write("ping over udp") != net::Err.None { print("write failed"); return; }
    let got, from, rerr = srv.read_from();
    if rerr != net::Err.None { print("read_from: ", rerr); return; }
    print("reçu ", got, " de ", from);

    if srv.write_to("pong", from) != net::Err.None { print("write_to failed"); return; }
    let back, perr = cli.read();
    if perr != net::Err.None { print("read: ", perr); return; }
    print("round trip udp: ", back);
}
