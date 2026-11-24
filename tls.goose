// TLS 1.3 client (RFC 8446), une suite : TLS_AES_128_GCM_SHA256, un
// groupe : x25519, une signature : ecdsa_secp256r1_sha256 — le GET
// HTTPS compose avec les seules briques du paquet, sans une ligne de C
// de plus. Le plan de cles, la couche enregistrement et le transcript
// suivent le RFC ; la verification du certificat demande une feuille
// dont la signature se verifie avec la cle qu'elle porte elle-meme
// (feuille auto-signee) et le nom dans les SAN, ce qui suffit au test
// local contre s_server. Le magasin de racines systeme reste a
// brancher pour l'usage general : la chaine n'est pas remontee.
//
// Les tampons sont a taille fixe pour que la connexion reste une valeur
// ordinaire, rendable par tls_connect — un enregistrement fait au plus
// 16645 octets (16 K + type + bourrage + tag) et un message de poignee
// complet tient dans le tampon de transcript. La seule partie croissante
// est le rbuf de la Conn, champ final.
namespace net;
import std;
import crypto.hash;
import crypto.aes;
import crypto.big;
import crypto.x25519;
import crypto.p256;

struct TlsConn {
    sec_r: bool = false,
    sec_w: bool = false,
    wr_key: u8[16] = [0; 16],
    wr_iv:  u8[12] = [0; 12],
    wr_seq: u64 = 0,
    rd_key: u8[16] = [0; 16],
    rd_iv:  u8[12] = [0; 12],
    rd_seq: u64 = 0,
    rbuf: u8[16800] = [0; 16800],     // les octets recus, du premier non lu
    rfill: i64 = 0,
    rpos: i64 = 0,
    hsbuf: u8[40000] = [0; 40000],    // les octets de poignee pas encore parses
    hsfill: i64 = 0,
    conn: Conn,
}

// l'entropie : /dev/urandom, ouverte par les externs de libc.goose. Le
// stdlib goose v2026.4 n'offre qu'un u64 de graine, insuffisant pour des
// cles ephernes ; on veut des octets comtes par le systeme
fn tls_random(out: u8[:]) -> bool {
    // le chemin finit par un nul, comme les chaines passees a C veulent
    var path: u8[>..] = [];
    path.append("/dev/urandom");
    path.push(0);
    let fd = sys_open(path[0], 0);
    if fd < 0 { return false; }
    var got = 0;
    while got < out.len {
        let n = sys_read(fd, out[got], (out.len - got) as u64);
        if n <= 0 {
            close(fd);
            return false;
        }
        got += n;
    }
    close(fd);
    return true;
}

// ---- la couche enregistrement (RFC 8446 5) ----

// le nonce : le IV statique XOR le numero d'ordre, en gros-boutien dans
// les 8 derniers octets
fn tls_nonce(iv: u8[12]&, seq: u64) -> u8[12] {
    var n: u8[12] = [0; 12];
    for i in 12 { n[i] = iv[i]; }
    var s = seq;
    var i = 11;
    while i >= 4 {
        n[i] ^= (s & 255) as u8;
        s >>= 8;
        i--;
    }
    return n;
}

// lit la socket jusqu'a couvrir want octets devant rpos ; le tampon se
// tasse au debut quand il n'a plus la place
fn tls_fill(t: TlsConn&, want: i64) -> Err {
    if t.rpos > 0 && t.rfill - t.rpos + want > t.rbuf.len {
        for i in t.rfill - t.rpos {
            t.rbuf[i] = t.rbuf[t.rpos + i];
        }
        t.rfill -= t.rpos;
        t.rpos = 0;
    }
    while t.rfill - t.rpos < want {
        let data, err = read(t.conn);
        if err != Err.None { return err; }
        if data.len == 0 { return Err.Closed; }
        if t.rfill + data.len > t.rbuf.len {
            return Err.Tls { text: "tampon d'entree sature" };
        }
        t.rbuf[t.rfill..t.rfill + data.len].move_from(data);
        t.rfill += data.len;
    }
    return Err.None;
}

// un enregistrement : le type reel et le texte clair, dechiffres si les
// cles de traffic sont posees ; sinon ServerHello ou l'alerte d'ouverture
fn tls_read_record(t: TlsConn&) -> u8, u8[>..], Err {
    let herr = tls_fill(t, 5);
    if herr != Err.None { return 0, [], herr; }
    let rtype = t.rbuf[t.rpos];
    let rlen = (t.rbuf[t.rpos + 3] as i64 << 8) | t.rbuf[t.rpos + 4];
    if rlen > 16640 { return 0, [], Err.Tls { text: "record trop grand" }; }
    let total = 5 + rlen;
    let ferr = tls_fill(t, total);
    if ferr != Err.None { return 0, [], ferr; }
    let at = t.rpos;

    if t.sec_r && rtype == 23 {
        var hdr: u8[5] = [0; 5];
        for i in 5 { hdr[i] = t.rbuf[at + i]; }
            let nonce = tls_nonce(t.rd_iv, t.rd_seq);
        t.rd_seq++;
        let ctlen = rlen - 16;
        var pt: u8[>..] = [];
        if !gcm128_open(t.rd_key[..], nonce, hdr[..], t.rbuf[at + 5..at + 5 + ctlen], t.rbuf[at + 5 + ctlen..at + total], pt) {
            return 0, [], Err.Tls { text: "tag gcm refuse" };
        }
        // bourrage a zero puis type reel a la fin (RFC 8446 5.4)
        var end = pt.len - 1;
        while end >= 0 && pt[end] == 0 { end--; }
        if end < 0 { return 0, [], Err.Tls { text: "record vide" }; }
        var out: u8[>..] = [];
        out.append(pt[..end]);
        t.rpos += total;
        if t.rpos == t.rfill { t.rpos = 0; t.rfill = 0; }
        return pt[end], out, Err.None;
    }

    var out: u8[>..] = [];
    out.append(t.rbuf[at + 5..at + total]);
    t.rpos += total;
    if t.rpos == t.rfill { t.rpos = 0; t.rfill = 0; }
    return rtype, out, Err.None;
}

// un enregistrement chiffre si les cles d'ecriture le sont : le type
// reel ferme le texte clair, l'entete porte le type apparent (RFC 5.2)
fn tls_write_record(t: TlsConn&, ctype: u8, data: const u8[:]) -> Err {
    var hdr: u8[5] = [0; 5];
    hdr[1] = 3;
    hdr[2] = 3;
    var out: u8[>..] = [];
    if t.sec_w {
        hdr[0] = 23;
        var pt: u8[>..] = [];
        pt.append(data);
        pt.push(ctype);
        let len = pt.len + 16;
        hdr[3] = (len >> 8) as u8;
        hdr[4] = len as u8;
        let nonce = tls_nonce(t.wr_iv, t.wr_seq);
        t.wr_seq++;
        let tag = gcm128_seal(t.wr_key[..], nonce, hdr[..], pt[..], out);
        out.append(tag[..]);
    } else {
        hdr[0] = ctype;
        let len = data.len;
        hdr[3] = (len >> 8) as u8;
        hdr[4] = len as u8;
        out.append(data);
    }
    var wire: u8[>..] = [];
    wire.append(hdr[..]);
    wire.append(out[..]);
    let _, werr = write(t.conn, wire[..]);
    if werr != Err.None { return werr; }
    return Err.None;
}

// ---- le plan de cles (RFC 8446 7.1) ----

// la cle AES et le IV du nonce pour un secret de traffic
fn tls_keys(secret: const u8[:]) -> u8[16], u8[12] {
    var kb: u8[>..] = [];
    var vb: u8[>..] = [];
    hkdf_expand_label256(secret, "key", [], 16, kb);
    hkdf_expand_label256(secret, "iv", [], 12, vb);
    var k: u8[16] = [0; 16];
    var v: u8[12] = [0; 12];
    if kb.len == 16 { k[..].move_from(kb[..]); }
    if vb.len == 12 { v[..].move_from(vb[..]); }
    return k, v;
}

fn get_u24be(d: const u8[:], at: i64) -> i64 {
    return (d[at] as i64 << 16) | (d[at + 1] as i64 << 8) | d[at + 2];
}

fn put_u24be(out: u8[>..]&, v: i64) {
    out.push((v >> 16) as u8);
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

// ---- le ClientHello ----

fn ext_push(out: u8[>..]&, kind: i64, body: const u8[:]) {
    put_u16be(out, kind as u16);
    put_u16be(out, body.len as u16);
    out.append(body);
}

// le message ClientHello entier, et le scalaire epherne qui va avec
fn tls_client_hello(host: const u8[:]) -> u8[>..], u8[32], Err {
    var eph: u8[32] = [0; 32];
    if !tls_random(eph[..]) {
        return [], eph, Err.Tls { text: "entropie absente" };
    }
    var base: u8[32] = [0; 32];
    base[0] = 9;                       // le point de base de Curve25519
    let pubk = x25519(eph[..], base[..]);

    var ext: u8[>..] = [];
    // server_name : la liste prefixee de sa longueur, puis l'entree
    var sni: u8[>..] = [];
    put_u16be(sni, (host.len + 3) as u16);
    sni.push(0);
    put_u16be(sni, host.len as u16);
    sni.append(host);
    ext_push(ext, 0x0000, sni[..]);
    var groups: u8[>..] = [];
    put_u16be(groups, 2);
    put_u16be(groups, 0x001d);         // x25519
    ext_push(ext, 0x000a, groups[..]);
    var sigs: u8[>..] = [];
    put_u16be(sigs, 2);
    put_u16be(sigs, 0x0403);           // ecdsa_secp256r1_sha256
    ext_push(ext, 0x000d, sigs[..]);
    var vers: u8[>..] = [];
    vers.push(2);
    put_u16be(vers, 0x0304);
    ext_push(ext, 0x002b, vers[..]);
    var ks: u8[>..] = [];
    put_u16be(ks, 36);
    put_u16be(ks, 0x001d);
    put_u16be(ks, 32);
    ks.append(pubk[..]);
    ext_push(ext, 0x0033, ks[..]);

    var body: u8[>..] = [];
    body.push(3);
    body.push(3);
    var rnd: u8[32] = [0; 32];
    if !tls_random(rnd[..]) {
        return [], eph, Err.Tls { text: "entropie absente" };
    }
    body.append(rnd[..]);
    // une session au hasard : la compatibilite milieu de boite l'exige
    var sid: u8[32] = [0; 32];
    if !tls_random(sid[..]) {
        return [], eph, Err.Tls { text: "entropie absente" };
    }
    body.push(32);
    body.append(sid[..]);
    put_u16be(body, 2);
    body.push(0x13);
    body.push(0x01);
    body.push(1);
    body.push(0);
    put_u16be(body, ext.len as u16);
    body.append(ext[..]);

    var msg: u8[>..] = [];
    msg.push(1);                       // handshake ClientHello
    put_u24be(msg, body.len);
    msg.append(body[..]);
    return msg, eph, Err.None;
}

// le ServerHello : la version, la suite, et la cle du serveur
fn tls_parse_sh(body: const u8[:]) -> u8[32], Err {
    var spub: u8[32] = [0; 32];
    if body.len < 39 { return spub, Err.Tls { text: "ServerHello court" }; }
    if body[0] != 3 || body[1] != 3 {
        return spub, Err.Tls { text: "pas un ServerHello" };
    }
    var at = 34;
    let sidlen = body[at] as i64;
    at += 1 + sidlen;
    if body.len < at + 4 || body[at] != 0x13 || body[at + 1] != 0x01 {
        return spub, Err.Tls { text: "suite non proposee" };
    }
    at += 3;
    if at + 2 > body.len { return spub, Err.Tls { text: "pas d'extensions" }; }
    let end = at + 2 + ((body[at] as i64 << 8) | body[at + 1]);
    at += 2;
    var got_v = false;
    var got_k = false;
    while at + 4 <= end {
        let kind = (body[at] as i64 << 8) | body[at + 1];
        let elen = (body[at + 2] as i64 << 8) | body[at + 3];
        at += 4;
        if at + elen > end { break; }
        // dans le ServerHello, la version seche et l'entree de cle sans
        // les prefixes de liste qu'on a mis dans le ClientHello
        if kind == 0x002b && elen == 2 && body[at] == 3 && body[at + 1] == 4 {
            got_v = true;
        }
        // la cle : le groupe, sa longueur, puis 32 octets
        if kind == 0x0033 && elen == 36 && body[at] == 0 && body[at + 1] == 0x1d && body[at + 2] == 0 && body[at + 3] == 32 {
            for i in 32 { spub[i] = body[at + 4 + i]; }
            got_k = true;
        }
        at += elen;
    }
    if !got_v || !got_k {
        return spub, Err.Tls { text: "pas de 1.3 ou de cle x25519" };
    }
    return spub, Err.None;
}

// ---- le certificat (X.509 lu a la main) ----

// le contenu d'un element DER : debut, fin exclusive, ok
fn der_span(d: const u8[:], at: i64) -> i64, i64, bool {
    if at + 2 > d.len { return 0, 0, false; }
    let lb = der_len_bytes(d, at + 1);
    let len = der_read_len(d, at + 1);
    if len < 0 { return 0, 0, false; }
    let start = at + 1 + lb;
    if start + len > d.len { return 0, 0, false; }
    return start, start + len, true;
}

fn lower(c: u8) -> u8 {
    if c >= 65 && c <= 90 { return c + 32; }
    return c;
}

fn tls_host_ok(exts: const u8[:], host: const u8[:]) -> bool {
    let q0, q1, ok = der_span(exts, 0);
    if !ok { return false; }
    var at = q0;
    while at < q1 {
        let x0, x1, okx = der_span(exts, at);
        if !okx { return false; }
        // chaque extension : l'OID, un critique eventuel, l'OCTET STRING.
        // Le dernier enfant porte les octets, le premier l'OID
        var oid0 = 0;
        var oct0 = 0;
        var is_san = false;
        var ch = x0;
        while ch < x1 {
            let a0, a1, oka = der_span(exts, ch);
            if !oka { return false; }
            if exts[ch] == 6 && a1 - a0 == 3 && exts[a0] == 0x55 && exts[a0 + 1] == 0x1d && exts[a0 + 2] == 0x11 {
                is_san = true;
            }
            oid0 = a0;
            oct0 = a0;
            ch = a1;
        }
        if is_san && ch > x0 {
            let i0, i1, oki = der_span(exts, oct0);
            if oki {
                var n = i0;
                while n < i1 {
                    let g0, g1, okg = der_span(exts, n);
                    if !okg { return false; }
                    // GeneralName [2] = dNSName
                    if exts[n] == 0x82 && g1 - g0 == host.len {
                        var eq = true;
                        for i in host.len {
                            if lower(exts[g0 + i]) != lower(host[i]) { eq = false; }
                        }
                        if eq { return true; }
                    }
                    n = g1;
                }
            }
        }
        at = x1;
    }
    return false;
}

// la feuille : sa cle, et la preuve qu'elle a signe son propre tbs.
// Le hostname doit figurer dans les SAN. La cle revient pour la
// CertificateVerify qui suit.
fn tls_check_cert(msg: const u8[:], host: const u8[:]) -> Big, Big, Err {
    var px = Big { .. };
    var py = Big { .. };
    if msg.len < 6 { return px, py, Err.Tls { text: "Certificate court" }; }
    let ctxlen = msg[0] as i64;
    var at = 1 + ctxlen;
    if at + 6 > msg.len { return px, py, Err.Tls { text: "Certificate court" }; }
    let clen = get_u24be(msg, at);
    at += 3;
    if at + clen > msg.len { return px, py, Err.Tls { text: "certificat tronque" }; }
    // la liste porte plusieurs entrees, chacune longues de son u24 :
    // la premiere est la feuille
    let elen = get_u24be(msg, at);
    at += 3;
    if elen > clen || at + elen > msg.len {
        return px, py, Err.Tls { text: "certificat tronque" };
    }
    let der = msg[at..at + elen];

    // Certificate ::= SEQUENCE { tbs, sigAlg, sigValue }
    let o0, o1, ok1 = der_span(der[..], 0);
    if !ok1 { return px, py, Err.Tls { text: "certificat der" }; }
    let s0, s1, ok2 = der_span(der[..], o0);
    if !ok2 { return px, py, Err.Tls { text: "tbs absent" }; }

    // tbs : [0] version, serial, sigAlg, issuer, validity, subject, spki, [3]
    var w = s0;
    let v0, v1, okv0 = der_span(der[..], w);
    if !okv0 { return px, py, Err.Tls { text: "tbs der" }; }
    if der[w] == 0xa0 { w = v1; }
    for i in 5 {
        let a0, a1, oki = der_span(der[..], w);
        if !oki { return px, py, Err.Tls { text: "tbs der" }; }
        w = a1;
    }
    let p0, p1, okp = der_span(der[..], w);       // subjectPublicKeyInfo
    if !okp { return px, py, Err.Tls { text: "spki absent" }; }
    let e0, e1, oke = der_span(der[..], p1);      // [3] extensions
    if !oke { return px, py, Err.Tls { text: "extensions absentes" }; }

    // la cle : l'algorithme, puis la BIT STRING, 00 || 04 || x || y sur 66
    let alg0, alg1, oka = der_span(der[..], p0);
    if !oka { return px, py, Err.Tls { text: "spki der" }; }
    let k0, k1, okk = der_span(der[..], alg1);
    if !okk || k1 - k0 != 66 || der[k0] != 0 || der[k0 + 1] != 4 {
        return px, py, Err.Tls { text: "cle P-256 absente" };
    }
    px = big_from_be(der[k0 + 2..k0 + 34]);
    py = big_from_be(der[k0 + 34..k0 + 66]);

    // la preuve de possession : le tbs signe par sa propre cle
    let g0, g1, okg = der_span(der[..], s1);      // signatureAlgorithm
    if !okg { return px, py, Err.Tls { text: "certificat der" }; }
    let b0, b1, okb = der_span(der[..], g1);      // signatureValue BIT STRING
    if !okb || b1 - b0 < 3 || der[b0] != 0 {
        return px, py, Err.Tls { text: "signature absente" };
    }
    // la signature couvre le tbsCertificate entier, entete comprise
    if !p256_verify(px, py, der[o0..s1], der[b0 + 1..b1]) {
        return px, py, Err.Tls { text: "certificat non signe par sa cle" };
    }
    if !tls_host_ok(der[e0..e1], host) {
        return px, py, Err.Tls { text: "nom hors des SAN" };
    }
    return px, py, Err.None;
}

// ---- la poignee de main ----

fn tls_handshake(t: TlsConn&, host: const u8[:]) -> Err {
    var hs: u8[>..] = [];              // le transcript entier

    let chmsg, eph, cherr = tls_client_hello(host);
    if cherr != Err.None { return cherr; }
    hs.append(chmsg[..]);
    var rec: u8[>..] = [];
    rec.push(0x16);
    rec.push(3);
    rec.push(1);
    put_u16be(rec, chmsg.len as u16);
    rec.append(chmsg[..]);
    let _, werr = write(t.conn, rec[..]);
    if werr != Err.None { return werr; }

    let rt, sh, rerr = tls_read_record(t);
    if rerr != Err.None { return rerr; }
    if rt == 21 { return Err.Tls { text: "alerte au ServerHello" }; }
    if rt != 22 { return Err.Tls { text: "ServerHello attendu" }; }
    hs.append(sh[..]);
    if sh.len < 4 { return Err.Tls { text: "ServerHello tronque" }; }
    // le message porte son entete (type, longueur sur 3) ; le transcript
    // garde l'entete, l'analyse ne prend que le corps
    let spub, perr = tls_parse_sh(sh[4..]);
    if perr != Err.None { return perr; }

    // l'echange, puis le plan : early -> derived -> handshake (RFC 7.1)
    let shared = x25519(eph[..], spub[..]);
    var zeros: u8[32] = [0; 32];
    let early = hkdf_extract256(zeros[..], zeros[..]);
    var salt: u8[32] = [0; 32];
    derive_secret256(early, "derived", "", salt);
    let hsecret = hkdf_extract256(salt[..], shared[..]);
    var c_hs: u8[32] = [0; 32];
    var s_hs: u8[32] = [0; 32];
    derive_secret256(hsecret, "c hs traffic", hs[..], c_hs);
    derive_secret256(hsecret, "s hs traffic", hs[..], s_hs);
    let wk, wiv = tls_keys(c_hs[..]);
    let rk, riv = tls_keys(s_hs[..]);
    t.wr_key = wk;
    t.wr_iv = wiv;
    t.wr_seq = 0;
    t.rd_key = rk;
    t.rd_iv = riv;
    t.rd_seq = 0;
    t.sec_w = true;
    t.sec_r = true;

    // {EncryptedExtensions, Certificate, CertificateVerify, Finished},
    // sous les cles de handshake, eventuellement fragmentes en records
    var qx = Big { .. };
    var qy = Big { .. };
    var saw_cert = false;
    var saw_fin = false;
    while !saw_fin {
        let rt2, body, rerr2 = tls_read_record(t);
        if rerr2 != Err.None { return rerr2; }
        if rt2 == 20 { continue; }   // change_cipher_spec de compatibilite
        if rt2 == 21 { return Err.Tls { text: "alerte pendant la poignee" }; }
        if rt2 != 22 { return Err.Tls { text: "enregistrement inattendu" }; }
        if t.hsfill + body.len > t.hsbuf.len {
            return Err.Tls { text: "transcript sature" };
        }
        t.hsbuf[t.hsfill..t.hsfill + body.len].move_from(body[..]);
        t.hsfill += body.len;
        while !saw_fin && t.hsfill >= 4 {
            let mtype = t.hsbuf[0];
            let mlen = get_u24be(t.hsbuf[..], 1);
            if t.hsfill < 4 + mlen { break; }
            let mtotal = 4 + mlen;
            if mtype == 8 {              // EncryptedExtensions
                hs.append(t.hsbuf[..mtotal]);
            } else if mtype == 11 {      // Certificate
                hs.append(t.hsbuf[..mtotal]);
                let cx, cy, cerr = tls_check_cert(t.hsbuf[4..mtotal], host);
                if cerr != Err.None { return cerr; }
                qx = cx;
                qy = cy;
                saw_cert = true;
            } else if mtype == 15 {      // CertificateVerify
                if !saw_cert { return Err.Tls { text: "certificat avant la signature" }; }
                if mlen < 4 { return Err.Tls { text: "CertificateVerify court" }; }
                let alg = (t.hsbuf[4] as i64 << 8) | t.hsbuf[5];
                let slen = (t.hsbuf[6] as i64 << 8) | t.hsbuf[7];
                if alg != 0x0403 || mlen < 4 + slen {
                    return Err.Tls { text: "signature non proposee" };
                }
                // le texte signe : contextes, etiquette, nul, hash du
                // transcript SANS ce message (RFC 8446 4.4.3)
                let th = sha256(hs[..]);
                hs.append(t.hsbuf[..mtotal]);
                var sign_in: u8[>..] = [];
                for i in 64 { sign_in.push(0x20); }
                sign_in.append("TLS 1.3, server CertificateVerify");
                sign_in.push(0);
                sign_in.append(th[..]);
                if !p256_verify(qx, qy, sign_in[..], t.hsbuf[8..8 + slen]) {
                    return Err.Tls { text: "signature du serveur refusee" };
                }
            } else if mtype == 0x14 {     // Finished
                if mlen != 32 { return Err.Tls { text: "Finished court" }; }
                // la preuve du serveur : HMAC sur le transcript jusqu'au
                // CertificateVerify, donc sans ce message
                var fk: u8[>..] = [];
                hkdf_expand_label256(s_hs[..], "finished", [], 32, fk);
                let thf = sha256(hs[..]);
                hs.append(t.hsbuf[..mtotal]);
                // la preuve est un HMAC sec, pas un expand : pas de compteur
                var want: u8[32] = hmac256(fk[..], thf[..]);
                var eq = true;
                for i in 32 {
                    if t.hsbuf[4 + i] != want[i] { eq = false; }
                }
                if !eq { return Err.Tls { text: "Finished du serveur refuse" }; }
                saw_fin = true;
            } else {
                return Err.Tls { text: "message de poignee inconnu" };
            }
            // le message est consomme, le reste remonte au debut
            for i in t.hsfill - mtotal {
                t.hsbuf[i] = t.hsbuf[mtotal + i];
            }
            t.hsfill -= mtotal;
        }
    }

    // master et cles d'application, sur le transcript jusqu'au Finished
    // du serveur
    var salt2: u8[32] = [0; 32];
    derive_secret256(hsecret, "derived", "", salt2);
    let master = hkdf_extract256(salt2[..], zeros[..]);
    var c_ap: u8[32] = [0; 32];
    var s_ap: u8[32] = [0; 32];
    derive_secret256(master, "c ap traffic", hs[..], c_ap);
    derive_secret256(master, "s ap traffic", hs[..], s_ap);
    let srk, sriv = tls_keys(s_ap[..]);

    // notre Finished part sous les cles de handshake, avant le switch
    var fk_c: u8[>..] = [];
    hkdf_expand_label256(c_hs[..], "finished", [], 32, fk_c);
    let th2 = sha256(hs[..]);
    var finb: u8[32] = hmac256(fk_c[..], th2[..]);
    var fmsg: u8[>..] = [];
    fmsg.push(0x14);                 // handshake Finished
    put_u24be(fmsg, 32);
    fmsg.append(finb[..]);
    let ferr = tls_write_record(t, 22, fmsg[..]);
    if ferr != Err.None { return ferr; }

    // puis on ecrit et on lit sous les cles d'application
    let cwk, cwiv = tls_keys(c_ap[..]);
    t.wr_key = cwk;
    t.wr_iv = cwiv;
    t.wr_seq = 0;
    t.rd_key = srk;
    t.rd_iv = sriv;
    t.rd_seq = 0;
    return Err.None;
}

// ---- l'usage ----

// connecte et fait la poignee ; name est le nom que le certificat doit
// porter (les SAN), host l'adresse du serveur
fn tls_connect(host: const u8[:], port: i64, name: const u8[:], secs: f64 = 0) -> TlsConn, Err {
    let c, cerr = connect(host, port, secs);
    if cerr != Err.None { return TlsConn { conn: Conn { fd: -1, .. } }, cerr; }
    if secs > 0 { set_timeout(c, secs); }
    var t = TlsConn { conn: copy(c) };
    let herr = tls_handshake(t, name);
    if herr != Err.None {
        close(t.conn);
        return TlsConn { conn: Conn { fd: -1, .. } }, herr;
    }
    return t, Err.None;
}

// une requete GET et la reponse entiere, jusqu'a close_notify ou fermeture
fn tls_get(t: TlsConn&, path: const u8[:]) -> u8[>..], Err {
    var req: u8[>..] = [];
    req.append("GET ");
    req.append(path);
    req.append(" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let werr = tls_write_record(t, 23, req[..]);
    if werr != Err.None { return [], werr; }
    var out: u8[>..] = [];
    loop {
        let rt, body, err = tls_read_record(t);
        if err != Err.None { return out, err; }
        if rt == 23 {
            out.append(body[..]);
        } else if rt == 21 {
            break;                     // close_notify : la fin propre
        } else if rt == 22 {
            // NewSessionTicket : on ne renegocie pas, on ignore
        } else {
            return out, Err.Tls { text: "enregistrement inattendu" };
        }
    }
    return out, Err.None;
}

fn tls_close(t: TlsConn&) {
    // close_notify, sans attendre l'acquittement
    var cl: u8[2] = [1, 0];
    tls_write_record(t, 21, cl[..]);
    close(t.conn);
}
