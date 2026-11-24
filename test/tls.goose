// La poignee TLS 1.3 de bout en bout contre s_server (cf. tls_e2e.sh) :
// le serveur sert son certificat P-256 auto-signe, le client le
// verifie (cle + SAN), derive les cles, et relit le corps du GET.
//   sh test/tls_e2e.sh
namespace net;
import net from "..";
import std;

fn ::main() { net::run(); }

fn run() {
    let t, err = tls_connect("localhost", 4461, "localhost", 5.0);
    if err != Err.None { print("tls connect: ", err); exit(1); }
    let resp, gerr = tls_get(t, "/localhost.pem");
    tls_close(t);
    if gerr != Err.None { print("tls get: ", gerr); exit(1); }

    // le corps doit contenir le pem demande : les donnees d'application
    // sont bien passees dans les deux sens
    const needle: const u8[:] = "BEGIN CERTIFICATE";
    var found = false;
    for i in resp.len - needle.len + 1 {
        var eq = true;
        for j in needle.len {
            if resp[i + j] != needle[j] { eq = false; }
        }
        if eq { found = true; }
    }
    if found {
        print("tls e2e ok (", resp.len, " octets)");
    } else {
        print("tls e2e: reponse sans le pem (", resp.len, " octets)");
        exit(1);
    }
}
