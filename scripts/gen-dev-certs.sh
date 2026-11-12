#!/usr/bin/env bash
# Generate a throwaway PKI for local docker-compose: a CA, a server certificate for
# localhost/api.localhost/app.localhost, and a client certificate for mutual TLS.
# Output: infra/nginx/certs/ (git-ignored). Never use these outside development.
set -euo pipefail

OUT="$(cd "$(dirname "$0")/.." && pwd)/infra/nginx/certs"
mkdir -p "$OUT"
cd "$OUT"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -keyout ca-key.pem -out ca.pem -subj "/CN=CipherCompute Dev CA"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server-key.pem -out server.csr -subj "/CN=localhost"
printf "subjectAltName=DNS:localhost,DNS:api.localhost,DNS:app.localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 30 -out server.pem -extfile server.ext

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout client-key.pem -out client.csr -subj "/CN=ciphercompute-sdk"
printf "extendedKeyUsage=clientAuth\n" > client.ext
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 30 -out client.pem -extfile client.ext

cp ca.pem client-ca.pem
rm -f ./*.csr ./*.ext ./*.srl
chmod 600 ./*-key.pem
echo "Wrote dev certificates to $OUT"
echo "SDK: TransportConfig(ca_file='$OUT/ca.pem', client_cert='$OUT/client.pem', client_key='$OUT/client-key.pem')"
