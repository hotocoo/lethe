#!/bin/bash
# Provision the one client identity used by Lethe's HTTPS/HTTP2 proxy.
# The client private key is imported into the macOS login keychain and is
# never consumed by Lethe itself; Chromium/CEF selects it via mTLS.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This helper is macOS-only." >&2
  exit 1
fi
APP_PATH="${1:-}"
if [[ -z "$APP_PATH" || ! -d "$APP_PATH" ]]; then
  echo "usage: $0 /path/to/lethe-cef.app" >&2
  exit 2
fi

OPENSSL="$(command -v openssl)"
SECURITY="$(command -v security)"
ROOT="$HOME/Library/Application Support/Lethe CEF/CEF Proxy"
CA="$ROOT/client-ca.crt"
TMP="$(mktemp -d /tmp/lethe-cef-identity.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$ROOT"
chmod 700 "$ROOT"

if [[ -e "$CA" ]]; then
  echo "CA already exists: $CA" >&2
  echo "For rotation, remove the CA and old keychain identity first." >&2
  exit 1
fi

"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$TMP/ca.key"
"$OPENSSL" req -x509 -new -sha256 -days 3650 \
  -key "$TMP/ca.key" -subj '/CN=Lethe CEF Proxy Client CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' -out "$CA"
"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$TMP/client.key"
"$OPENSSL" req -new -sha256 -key "$TMP/client.key" \
  -subj '/CN=Lethe CEF Proxy Client' -out "$TMP/client.csr"
cat > "$TMP/client.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
"$OPENSSL" x509 -req -sha256 -days 30 \
  -in "$TMP/client.csr" -CA "$CA" -CAkey "$TMP/ca.key" -CAcreateserial \
  -extfile "$TMP/client.ext" -out "$TMP/client.crt"

LOGIN_KEYCHAIN="$(security default-keychain -d user | sed -E 's/^[[:space:]]*"//; s/"[[:space:]]*$//')"
security delete-certificate -c 'Lethe CEF Proxy Client' "$LOGIN_KEYCHAIN" >/dev/null 2>&1 || true
"$OPENSSL" pkcs12 -export -inkey "$TMP/client.key" \
  -in "$TMP/client.crt" -certfile "$CA" \
  -name 'Lethe CEF Proxy Client' \
  -passout pass:lethe-cef-provision -out "$TMP/client.p12"

# Do not use security import -A (which grants every application access).
IMPORT_ARGS=("$TMP/client.p12" -k "$LOGIN_KEYCHAIN" -P lethe-cef-provision)
IMPORT_ARGS+=( -T "$APP_PATH/Contents/MacOS/lethe-cef" )
while IFS= read -r helper; do IMPORT_ARGS+=( -T "$helper" ); done < <(
  find "$APP_PATH/Contents/Frameworks" -type f -perm -111 2>/dev/null
)
"$SECURITY" import "${IMPORT_ARGS[@]}" -t agg -f pkcs12 -x >/dev/null

# CEF's macOS client-certificate enumeration requires the certificate and
# private key to form a valid keychain identity. Do not report provisioning
# success when macOS imported only the certificate (which can happen when the
# PKCS#12 friendly name does not match the certificate identity metadata).
if ! "$SECURITY" find-identity -v -p ssl-client "$LOGIN_KEYCHAIN" 2>/dev/null |
    grep -Fq 'Lethe CEF Proxy Client'; then
  echo "ERROR: macOS did not create a valid Lethe CEF client identity" >&2
  exit 1
fi

rm -f "$TMP/ca.key" "$TMP/client.key" "$TMP/client.p12"
chmod 600 "$CA"
echo "Provisioned: Lethe CEF Proxy Client"
echo "CA: $CA"
echo "Verify: security find-identity -v -p ssl-client"
echo "Enable: LETHE_CEF_HTTPS_PROXY=1 LETHE_CEF_HTTPS_PROXY_AUTH=client-cert"
