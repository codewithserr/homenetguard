#!/usr/bin/env bash
set -e

OS="$(uname -s)"
echo "Installing system dependencies for HomeNetGuard on $OS..."

if [ "$OS" = "Linux" ]; then
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y tshark libpcap-dev python3-dev build-essential \
            libcairo2-dev libpango1.0-dev libgdk-pixbuf2.0-dev libffi-dev
        echo "Installed via apt"
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y wireshark-cli libpcap-devel python3-devel gcc \
            cairo-devel pango-devel gdk-pixbuf2-devel libffi-devel
        echo "Installed via dnf"
    else
        echo "Unsupported package manager — install tshark and libpcap manually"
        exit 1
    fi
elif [ "$OS" = "Darwin" ]; then
    if ! command -v brew &>/dev/null; then
        echo "Homebrew not found — install from https://brew.sh"
        exit 1
    fi
    brew install wireshark libpcap cairo pango gdk-pixbuf libffi
    echo "Installed via Homebrew"
    echo ""
    echo "To capture without sudo on macOS:"
    echo "  sudo dseditgroup -o edit -a \$USER -t user access_bpf"
else
    echo "Unsupported OS: $OS"
    exit 1
fi

echo ""
echo "System dependencies installed. Run 'make install-dev' next."
