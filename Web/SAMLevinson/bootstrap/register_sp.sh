#!/bin/sh
set -e

echo "Waiting for SP..."
until curl -fsS http://sp:8080/saml/metadata >/dev/null 2>&1; do
  sleep 1
done

echo "Waiting for IdP..."
until curl -fsS http://idp:8081/metadata >/dev/null 2>&1; do
  sleep 1
done

echo "Fetching SP metadata (original)"
curl -fsS http://sp:8080/saml/metadata > /tmp/sp.xml

echo "Stripping <KeyDescriptor use=\"encryption\"> from SP metadata"
awk '
  /<[^>]*KeyDescriptor[^>]*use="encryption"/ {skip=1; next}
  skip==1 && /<\/KeyDescriptor>/ {skip=0; next}
  skip==0 {print}
' /tmp/sp.xml > /tmp/sp-noenc.xml

echo "Registering SP in IdP without encryption key"
curl -fsS -X PUT \
  -H "Content-Type: application/xml" \
  --data-binary @/tmp/sp-noenc.xml \
  http://idp:8081/services/hero-sp

echo "SP loader in IdP (clear assertions)"
