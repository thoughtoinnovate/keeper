#!/bin/sh
set -e

# =================================================================
#  KEEPER INSTALLATION SCRIPT
# =================================================================
REPO_URL="https://github.com/thoughtoinnovate/keeper"
# =================================================================

BIN_NAME="keeper"
INSTALL_DIR="/usr/local/bin"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo "${BLUE}[INFO]${NC} $1"; }
log_success() { echo "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo "${RED}[ERROR]${NC} $1"; exit 1; }
log_warn() { echo "${RED}[WARN]${NC} $1"; }

log_info "Starting Keeper installer..."

# --- 1. Detect OS & Architecture ---
OS="$(uname -s)"
ARCH="$(uname -m)"
IS_WINDOWS=0

case "$OS" in
    Linux)  OS_TARGET="unknown-linux-gnu" ;;
    Darwin) OS_TARGET="apple-darwin" ;;
    MINGW*|MSYS*|CYGWIN*)
        OS_TARGET="pc-windows-msvc"
        IS_WINDOWS=1
        ;;
    *)      log_error "Unsupported operating system: $OS" ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH_TARGET="x86_64" ;;
    arm64|aarch64) ARCH_TARGET="aarch64" ;;
    *)            log_error "Unsupported architecture: $ARCH" ;;
esac

FULL_TARGET="${ARCH_TARGET}-${OS_TARGET}"

if [ "$IS_WINDOWS" -eq 1 ]; then
    ASSET_EXT="zip"
    BIN_EXT=".exe"
    INSTALL_DIR="${HOME}/.local/bin"
else
    ASSET_EXT="tar.gz"
    BIN_EXT=""
fi

ASSET_NAME="${BIN_NAME}-${FULL_TARGET}.${ASSET_EXT}"
DOWNLOAD_URL="${REPO_URL}/releases/latest/download/${ASSET_NAME}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

log_info "Detected system: $OS ($ARCH)"
log_info "Targeting release asset: $ASSET_NAME"

# --- 2. Pre-flight Checks ---
command -v curl >/dev/null 2>&1 || log_error "curl is required but not installed."
if [ "$IS_WINDOWS" -eq 1 ]; then
    if ! command -v unzip >/dev/null 2>&1 && ! command -v powershell >/dev/null 2>&1; then
        log_error "Either unzip or powershell is required but not installed."
    fi
else
    command -v tar >/dev/null 2>&1 || log_error "tar is required but not installed."
fi

# --- 3. Download & Extract ---
TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT

log_info "Downloading latest release..."
# Use -f to fail silently on server errors (like 404)
if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$ASSET_NAME"; then
    log_error "Download failed. Check connection or if release exists: $DOWNLOAD_URL"
fi

log_info "Downloading checksum..."
if ! curl -fsSL "$CHECKSUM_URL" -o "$TMP_DIR/$ASSET_NAME.sha256"; then
    log_error "Checksum download failed. Check connection or if release exists: $CHECKSUM_URL"
fi

calc_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
        return
    fi
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
        return
    fi
    if command -v certutil >/dev/null 2>&1; then
        certutil -hashfile "$1" SHA256 | sed -n '2p' | tr -d '\r'
        return
    fi
    log_error "No SHA-256 tool found (sha256sum, shasum, or certutil required)."
}

EXPECTED_HASH=$(awk '{print tolower($1)}' "$TMP_DIR/$ASSET_NAME.sha256" | tr -d '\r')
ACTUAL_HASH=$(calc_sha256 "$TMP_DIR/$ASSET_NAME" | tr '[:upper:]' '[:lower:]')
if [ -z "$EXPECTED_HASH" ] || [ -z "$ACTUAL_HASH" ]; then
    log_error "Checksum verification failed (empty hash)."
fi
if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
    log_error "Checksum mismatch. Expected $EXPECTED_HASH, got $ACTUAL_HASH"
fi
log_success "Checksum verified"

log_info "Extracting..."
if [ "$IS_WINDOWS" -eq 1 ]; then
    if command -v unzip >/dev/null 2>&1; then
        unzip -q "$TMP_DIR/$ASSET_NAME" -d "$TMP_DIR"
    else
        powershell -Command "Expand-Archive -Path '$TMP_DIR\\$ASSET_NAME' -DestinationPath '$TMP_DIR'" >/dev/null
    fi
else
    tar -xzf "$TMP_DIR/$ASSET_NAME" -C "$TMP_DIR"
fi

BIN_PATH="$TMP_DIR/$BIN_NAME$BIN_EXT"
if [ ! -f "$BIN_PATH" ]; then
    log_error "Extraction failed. Binary not found in archive."
fi

chmod +x "$BIN_PATH"

# --- 4. Install ---
log_info "Installing to $INSTALL_DIR (requires elevated permissions on Unix)..."

if [ "$IS_WINDOWS" -eq 1 ]; then
    mkdir -p "$INSTALL_DIR"
    mv "$BIN_PATH" "$INSTALL_DIR/$BIN_NAME$BIN_EXT"
else
    if [ -w "$INSTALL_DIR" ]; then
        mv "$BIN_PATH" "$INSTALL_DIR/$BIN_NAME"
    else
        if command -v sudo >/dev/null 2>&1; then
            sudo mv "$BIN_PATH" "$INSTALL_DIR/$BIN_NAME"
        else
           log_error "Cannot write to $INSTALL_DIR and 'sudo' is not available."
        fi
    fi
fi

# --- 5. Verify & Finish ---
BIN_CMD="$BIN_NAME$BIN_EXT"
if ! command -v "$BIN_CMD" >/dev/null 2>&1; then
    log_warn "'$BIN_CMD' is not in your PATH."
    log_warn "Add $INSTALL_DIR to your PATH, then re-run: $BIN_CMD --version"
    exit 0
fi

INSTALLED_VERSION=$("$BIN_CMD" --version)
log_success "Successfully installed: $INSTALLED_VERSION"
echo ""
echo "Try it out by running:"
echo "  keeper start"
