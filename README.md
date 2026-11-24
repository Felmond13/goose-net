# goose-net

Sockets TCP, UDP et Unix pour Goose, avec les primitives crypto qui vont
bien (SHA-2, HMAC/HKDF, AES-GCM, x25519, P-256) — le tout écrit en goose,
sans une ligne de C : les appels POSIX sont déclarés dans un bloc
`extern "libc"` et liés par le loader au démarrage du programme. goose
n'a ni syscall ni assembleur inline : déclarer la libc du système est la
seule porte vers le noyau — nos déclarations, jamais des
réimplémentations.

Bloquant par défaut, IPv4 et IPv6, noms de domaine résolus par
getaddrinfo, timeouts partout, multicast, happy-eyeballs. Le détail par
famille est dans les sections qui suivent.

```
goose-net/
  net.goose                 le paquet (+ `goose run net.goose` : test e2e)
  net.build                 le nom de la libc par plateforme + exclusions
  platform.goose            ce qui change d'un OS à l'autre (uname(2) tranche)
  libc.goose                le bloc extern "libc", errno, poll
  addr.goose                Addr, parse, texte, sockaddr
  dns.goose                 résolution + cache + dial parallèle (RFC 8305)
  tcp.goose, udp.goose, unix.goose
  tls.goose                 client TLS 1.3, une suite, un groupe
  crypto/                   hash, aes, big, x25519, p256 — vecteurs dans test/
  examples/                 echo TCP, udp, timeout
  test/                     vectors.goose, x25519.goose, p256.goose
```

## À quoi ça ressemble

```goose
let l, err = net::listen("::", 8080);      // v6, et v4 aussi (V6ONLY à 0)
if err != net::Err.None { print("listen: ", err); return; }

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
```

Côté client, un nom de domaine passe comme un littéral — connect essaie
les adresses dans l'ordre du résolveur, en parallèle décalé de 250 ms
entre familles (RFC 8305) :

```goose
let c, err = net::connect("localhost", 8080, 2.0);   // 2 s max, sinon TimedOut
```

UDP : `udp_bind` (sans peer), `udp_dial` (peer fixé), `read_from` rend
l'émetteur, `write_to` lui répond, `join`/`leave` pour le multicast.
Unix : `unix_listen`/`unix_connect` pour du stream, `unix_dgram` pour du
datagramme. `accept_loop` referme chaque connexion quand le bloc a fini
avec elle.

## Les erreurs

Chaque appel qui peut échouer rend une erreur en dernière valeur, un ADT
tout bête : `Sys` (l'appel POSIX + l'errno brut), `Name` (le code de
getaddrinfo), `Closed`, `TimedOut`, `BadAddr`, `BadPort`. `print(err)`
rend tout ça lisible parce que les hooks `format` passent par
`strerror` et `gai_strerror` :

```
connect: connect failed: Connection refused (errno 111)
resolve failed: Name or service not known
```

Le module ignore SIGPIPE à son premier `listen`/`connect` — sinon un
`write` vers un pair mort abattrait le programme avant que l'erreur
n'ait une chance d'être rendue.

## Les timeouts

Toutes les sockets naissent non-bloquantes (`SOCK_NONBLOCK`) et chaque
opération passe d'abord par `poll` : un seul mécanisme donne des
timeouts sur read/write/accept/connect, sans timeval dont le layout
change entre Linux et macOS, et sans fcntl (variadic, donc inbindable
par l'FFI).

```goose
conn.set_timeout(5.0);               // read/write ; 0 remet l'attente infinie
let c, err = net::connect(h, p, 2.0);
```

`write` rend le nombre d'octets partis avant l'erreur : avec un timeout,
un envoi peut partir à moitié (sémantique send(2), assumée). En UDP, un
datagramme part entier ou pas du tout, donc `write` rend juste Err.

## La mémoire

Rien ne va sur un tas : tout vit sur les data stacks de Goose. `read()`
ne copie rien — il rend une vue dans le tampon interne de la connexion,
et le tampon est réutilisé au `read` suivant. Si tu tiens encore une vue
du read précédent au moment du suivant, c'est le checker de Goose qui
te le dit.

## Les plateformes

Goose n'a pas de `#ifdef`, mais les initialiseurs de globales peuvent
appeler des fonctions, et les blocs extern sont liés avant que ces
initialiseurs ne tournent. Au démarrage, `uname(2)` est donc interrogé,
et les valeurs qui changent d'un OS à l'autre (`SOL_SOCKET`,
`SO_REUSEADDR`, `SO_ERROR`, `AF_INET6`, `EAGAIN`, `EINPROGRESS`,
`SOCK_NONBLOCK`, les options multicast) sont posées en conséquence.
Les octets supposent une machine little-endian.

Un piège au passage, puisqu'il a coûté une heure : chez Linux,
`SO_ERROR` vaut 4 — la valeur 3 est `SO_TYPE`, et un getsockopt sur la
mauvaise constante rend poliment le type de la socket au lieu de
l'erreur de connexion.

## Le domaine crypto (crypto/)

SHA-256/384/512 streaming, HMAC, HKDF, AES-128-GCM, x25519, un gros
entier avec réduction de Montgomery, et P-256 : ECDH et ECDSA
(SHA-256, k déterministe RFC 6979) — le tout en Goose, avec vecteurs
RFC dans `test/` croisés avec hashlib et cryptography d'un côté, le code
Goose de l'autre, et dans les deux sens : la signature goose est relue
par Python, la signature Python par goose. tls.goose compose le tout en
un client TLS 1.3 complet (section suivante).

Trois curiosités d'implémentation, au cas où : un `extern fn` goose ne
peut pas rendre une référence, donc errno voyage via `ffi::bytes`
depuis `__errno_location()` ; le REDC de mont_mul peut déborder sur
un neuvième mot de 32 bits — sans lui, la soustraction finale rate une
fois sur deux sur les grandes valeurs ; et la chaîne d'emprunt de
big_sub doit compter dans un u64 — `b + borrow` en u32 déborde pile
quand b vaut 0xffffffff, et l'emprunt perdu corrompt un chiffre sur
deux du divmod.

## Le TLS

tls.goose fait un client TLS 1.3 complet de bout en bout : ClientHello,
échange x25519, plan de clés du RFC 8446 sur les primitives du paquet,
EncryptedExtensions/Certificate/CertificateVerify/Finished déchiffrés
et vérifiés (clé, nom dans les SAN, signature du serveur, Finished en
HMAC sec), puis GET sous les clés d'application. La suite est unique —
TLS_AES_128_GCM_SHA256, x25519, ecdsa_secp256r1_sha256 — et ça suffit :

```goose
let t, err = net::tls_connect("localhost", 4433, "localhost", 5.0);
if err != net::Err.None { print("tls: ", err); return; }
let resp, gerr = net::tls_get(t, "/");
net::tls_close(t);
```

La vérification du certificat exige une feuille dont la signature se
vérifie avec la clé qu'elle porte (feuille auto-signée) et le nom dans
les SAN : c'est le contrat du test local contre `s_server`, pas d'un
magasin de racines. La remontée de chaîne et le magasin système restent
à brancher avant un usage général. Trois pièges du RFC, au cas où : le
HkdfLabel préfixe l'étiquette et le contexte d'un SEUL octet (des
vecteurs <7..255>, pas des u16) ; les deux Derive-Secret("derived", …)
hachent le transcript VIDE, pas le courant ; le Finished est un HMAC
sec sur le hash du transcript, pas un HKDF-Expand (le compteur en
débordrait) — et le type handshake Finished vaut 0x14, pas 14.

## Ce qui n'y est pas

Le magasin de racines et la remontée de chaîne du TLS (la feuille
auto-signée suffit au test local, pas au web). À côté : le scope des
adresses link-local (`fe80::%eth0`), la résolution asynchrone,
REUSEPORT côté multicast, TLS 1.2 et les suites AEAD autres que
AES-128-GCM.

## Essayer

```
goose run net.goose                          # v4 + v6 + udp + unix + mcast
goose run examples/echo_server.goose         # puis, ailleurs :
goose run examples/echo_client.goose         # ou nc 127.0.0.1 8080
goose run examples/udp_echo.goose
goose run examples/timeout.goose
goose run test/vectors.goose                 # les vecteurs RFC
goose run test/x25519.goose
goose run test/p256.goose
sh test/tls_e2e.sh                           # TLS 1.3 contre s_server
```

Le test local (dans le `fn ::main` de net.goose) écoute, se connecte via
le résolveur, échange dans les deux sens sur les deux familles, fait un
aller-retour UDP et unix, rejoint un groupe multicast et vérifie qu'un
timeout rend bien TimedOut. Le noyau termine un `connect` contre la
backlog avant le moindre `accept`, donc tout tient dans un seul
processus, sans threads.
