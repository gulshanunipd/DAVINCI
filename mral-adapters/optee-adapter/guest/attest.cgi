#!/bin/sh
# OP-TEE collector endpoint.
#   GET /cgi-bin/attest?op=pubkey
#   GET /cgi-bin/attest?op=attest&nonce=<hex>
echo "Content-Type: application/json"
echo ""
op=$(echo "$QUERY_STRING" | sed -n 's/.*op=\([a-z]*\).*/\1/p')
nonce=$(echo "$QUERY_STRING" | sed -n 's/.*nonce=\([0-9a-fA-F]*\).*/\1/p')
case "$op" in
  pubkey) exec /usr/bin/davinci-attest pubkey ;;
  attest) exec /usr/bin/davinci-attest attest "$nonce" ;;
  *) echo '{"error":"unknown op"}' ;;
esac
