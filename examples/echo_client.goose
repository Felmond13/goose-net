// Envoie une ligne au serveur echo et affiche ce qui revient. Le serveur
// doit tourner (examples/echo_server.goose).
//
//   goose run examples/echo_client.goose
//
// "localhost" passe par le résolveur (getaddrinfo) : connect essaie les
// adresses dans l'ordre qu'il donne jusqu'à ce qu'une passe.
import net from "..";

fn main() {
    let c, cerr = net::connect("localhost", 8080);
    if cerr != net::Err.None { print("connect: ", cerr); return; }
    defer c.close();

    let _, werr = c.write("hello, goose");
    if werr != net::Err.None { print("write: ", werr); return; }
    let buf, rerr = c.read();
    if rerr != net::Err.None { print("read: ", rerr); return; }
    print("echo: ", buf);
}
