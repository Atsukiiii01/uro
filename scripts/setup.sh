#!/usr/bin/env bash
set -e

echo "[*] Initiating URO core environment setup..."

# 1. Python Virtual Environment & Dependencies
if [ ! -d "venv" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "[*] Activating virtual environment and installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
fi

# 2. Rust Native Compilation
echo "[*] Checking for Rust toolchain..."
if ! command -v cargo &> /dev/null; then
    echo "[-] Rust not found. Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

echo "[*] Compiling rust_core analysis engine..."
cd src-rust

# Fix for Python 3.14 + PyO3 limitations
export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1
export PYO3_PYTHON="$(pwd)/../venv/bin/python"

# Force macOS linker to allow unresolved Python symbols at compile time
if [[ "$OSTYPE" == "darwin"* ]]; then
    export RUSTFLAGS="-C link-arg=-undefined -C link-arg=dynamic_lookup"
fi

cargo build --release
cd ..

# Auto-copy the compiled binary for macOS or Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
    cp src-rust/target/release/liburo_rust_core.dylib uro_rust_core.so
else
    cp src-rust/target/release/liburo_rust_core.so uro_rust_core.so
fi

echo "[+] Setup complete. To activate the environment, run: source venv/bin/activate"