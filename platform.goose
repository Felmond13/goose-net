// Ce que l'OS nous donne et ce qui change d'un OS à l'autre. Goose n'a pas
// de #ifdef : uname(2) tranche au démarrage, et la spec garantit que les
// blocs extern sont liés avant que les initialiseurs de globales ne
// tournent. Les octets supposent une machine little-endian ; c'est le cas
// de tout ce qui exécute ce module en pratique.
namespace net;

// Les constantes qui ont la même valeur partout.
let AF_UNIX = 1;
let AF_INET = 2;
let SOCK_STREAM = 1;
let SOCK_DGRAM = 2;
let IPPROTO_IP = 0;
let IPPROTO_IPV6 = 41;
let POLLIN:  i16 = 1;
let POLLOUT: i16 = 4;
let SIGPIPE = 13;
let SIG_IGN = 1;
let CHUNK = 16384;
let UDPMAX = 65507;     // la charge utile d'un datagramme, l'IPv4 en tête
let STAGGER_NS = 250000000;     // le départ décalé de la RFC 8305, en ns

var OS_DARWIN = uname_darwin();
var SOL_SOCKET:   i32 = if OS_DARWIN { 0xffff } else { 1 };
var SO_REUSEADDR: i32 = if OS_DARWIN { 4 } else { 2 };
var SO_REUSEPORT: i32 = if OS_DARWIN { 0x0200 } else { 15 };
var AF_INET6:     i32 = if OS_DARWIN { 30 } else { 10 };
var IPV6_V6ONLY:  i32 = if OS_DARWIN { 27 } else { 26 };
// piège classique : 3 est SO_TYPE chez Linux, SO_ERROR y vaut 4
var SO_ERROR:            i32 = if OS_DARWIN { 0x1007 } else { 4 };
var EAGAIN:              i32 = if OS_DARWIN { 35 } else { 11 };
var EINPROGRESS:         i32 = if OS_DARWIN { 36 } else { 115 };
var SOCK_NONBLOCK:       i32 = if OS_DARWIN { 0x4000 } else { 0x800 };
var IP_ADD_MEMBERSHIP:   i32 = if OS_DARWIN { 12 } else { 35 };
var IP_DROP_MEMBERSHIP:  i32 = if OS_DARWIN { 13 } else { 36 };
var IP_MULTICAST_TTL:    i32 = if OS_DARWIN { 10 } else { 33 };
var IP_MULTICAST_LOOP:   i32 = if OS_DARWIN { 11 } else { 34 };
var IPV6_JOIN_GROUP:     i32 = if OS_DARWIN { 12 } else { 20 };
var IPV6_LEAVE_GROUP:    i32 = if OS_DARWIN { 13 } else { 21 };
var IP_MULTICAST_IF:     i32 = if OS_DARWIN { 9 } else { 32 };
var IPV6_MULTICAST_IF:   i32 = if OS_DARWIN { 9 } else { 17 };
var IPV6_MULTICAST_HOPS: i32 = if OS_DARWIN { 10 } else { 18 };
var IPV6_MULTICAST_LOOP: i32 = if OS_DARWIN { 11 } else { 19 };

// sysname est le premier champ du utsname ; "Darwin" sur macOS, peu
// importe la taille réelle des champs tant qu'on coupe au premier NUL.
fn uname_darwin() -> bool {
    var buf: u8[2048] = [0; 2048];
    if uname(buf[0]) != 0 { return false; }
    let end = find(buf[..], "\0");
    guard end > 0 else { return false; }
    return compare(buf[..end], "Darwin") == 0;
}
