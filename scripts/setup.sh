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