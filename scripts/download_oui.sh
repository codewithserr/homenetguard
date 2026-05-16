#!/usr/bin/env bash
set -e

DEST="config/oui/oui.txt"

if [ -f "$DEST" ]; then
    echo "OUI database already exists at $DEST ($(wc -l < "$DEST") lines)"
    echo "Delete it to re-download."
    exit 0
fi

mkdir -p config/oui
echo "Downloading IEEE OUI database..."
curl -fsSL "https://standards-oui.ieee.org/oui/oui.txt" -o "$DEST"
echo "OUI database downloaded: $(wc -l < "$DEST") lines at $DEST"
