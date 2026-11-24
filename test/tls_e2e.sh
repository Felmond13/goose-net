#!/bin/sh
# La poignee TLS de bout en bout : un certificat P-256 auto-signe pour
# localhost, s_server -WWW qui le sert, puis le client goose qui fait
# la poignee, verifie le certificat et relit le corps du GET.
cd "$(dirname "$0")"
if [ ! -f localhost.pem ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout localhost.key -out localhost.pem -days 30 -nodes \
        -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
        -sha256 >/dev/null 2>&1 || openssl req -x509 -newkey ec:localhost.key \
        -keyout localhost.key -out localhost.pem -days 30 -nodes \
        -subj "/CN=localhost" -sha256
fi
openssl s_server -accept 4461 -WWW -cert localhost.pem -key localhost.key -quiet >/dev/null 2>&1 &
SRV=$!
sleep 1
goose run tls.goose
RC=$?
kill $SRV 2>/dev/null
exit $RC
