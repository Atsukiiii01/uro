Write-Host "[*] Initiating URO core environment setup for Windows..."

# 1. Python Virtual Environment
if (-Not (Test-Path "venv")) {
    Write-Host "[*] Creating Python virtual environment..."
    python -m venv venv
}

Write-Host "[*] Installing Python dependencies..."
& .\venv\Scripts\python.exe -m pip install --upgrade pip
& .\venv\Scripts\python.exe -m pip install -r requirements.txt

# 2. Rust Native Compilation
Write-Host "[*] Checking for Rust toolchain..."
if (-Not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
    Write-Host "[-] CRITICAL: Rust not found."
    Write-Host "[-] Windows requires manual Rust installation. Download and run rustup-init.exe from https://rustup.rs/"
    exit 1
}

Write-Host "[*] Compiling rust_core analysis engine..."
Set-Location -Path "src-rust"
$env:PYO3_USE_ABI3_FORWARD_COMPATIBILITY="1"
cargo build --release
Set-Location -Path ".."

# Auto-copy the compiled binary for Windows (.dll to .pyd so Python can import it natively)
$rust_dll = "src-rust\target\release\uro_rust_core.dll"
if (Test-Path $rust_dll) {
    Copy-Item -Path $rust_dll -Destination "uro_rust_core.pyd" -Force
    Write-Host "[+] Rust engine compiled and linked successfully."
} else {
    Write-Host "[-] Build failed: Could not find compiled DLL."
    exit 1
}

Write-Host "`n[+] Setup complete. To activate the environment, run:"
Write-Host "    .\venv\Scripts\activate"