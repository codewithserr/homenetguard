#!/usr/bin/env bash
set -e

DEST="config/geoip/GeoLite2-City.mmdb"

if [ -f "$DEST" ]; then
    echo "GeoIP database already exists at $DEST"
    exit 0
fi

mkdir -p config/geoip

# MaxMind requires a free account + license key
# Set MAXMIND_LICENSE_KEY env var or pass as argument
LICENSE_KEY="${1:-$MAXMIND_LICENSE_KEY}"

if [ -z "$LICENSE_KEY" ]; then
    echo "No MaxMind license key provided."
    echo "Get a free key at: https://www.maxmind.com/en/geolite2/signup"
    echo "Then run: MAXMIND_LICENSE_KEY=<key> bash scripts/download_geoip.sh"
    echo ""
    echo "Alternatively, download GeoLite2-City.mmdb manually and place it at:"
    echo "  $DEST"
    exit 1
fi

URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${LICENSE_KEY}&suffix=tar.gz"
TMP=$(mktemp -d)
echo "Downloading GeoLite2-City.mmdb..."
curl -fsSL "$URL" -o "$TMP/geoip.tar.gz"
tar -xzf "$TMP/geoip.tar.gz" -C "$TMP"
find "$TMP" -name "GeoLite2-City.mmdb" -exec mv {} "$DEST" \;
rm -rf "$TMP"
echo "GeoIP database saved to $DEST"
