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

# --- 1. Pre-flight Checks ---
command -v curl >/dev/null 2>&1 || log_error "curl is required but not installed."
command -v tar >/dev/null 2>&1 || log_error "tar is required but not installed."

log_info "Starting Keeper installer..."

# --- 2. Detect OS & Architecture ---
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  OS_TARGET="unknown-linux-gnu" ;;
    Darwin) OS_TARGET="apple-darwin" ;;
    *)      log_error "Unsupported operating system: $OS" ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH_TARGET="x86_64" ;;
    arm64|aarch64) ARCH_TARGET="aarch64" ;;
    *)            log_error "Unsupported architecture: $ARCH" ;;
esac

FULL_TARGET="${ARCH_TARGET}-${OS_TARGET}"
ASSET_NAME="${BIN_NAME}-${FULL_TARGET}.tar.gz"
DOWNLOAD_URL="${REPO_URL}/releases/latest/download/${ASSET_NAME}"

log_info "Detected system: $OS ($ARCH)"
log_info "Targeting release asset: $ASSET_NAME"

# --- 3. Download & Extract ---
TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT

log_info "Downloading latest release..."
# Use -f to fail silently on server errors (like 404)
if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$ASSET_NAME"; then
    log_error "Download failed. Check connection or if release exists: $DOWNLOAD_URL"
fi

log_info "Extracting..."
tar -xzf "$TMP_DIR/$ASSET_NAME" -C "$TMP_DIR"

if [ ! -f "$TMP_DIR/$BIN_NAME" ]; then
    log_error "Extraction failed. Binary not found in archive."
fi

chmod +x "$TMP_DIR/$BIN_NAME"

# --- 4. Install ---
log_info "Installing to $INSTALL_DIR (requires elevated permissions)..."

if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP_DIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
else
    if command -v sudo >/dev/null 2>&1; then
        sudo mv "$TMP_DIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
    else
       log_error "Cannot write to $INSTALL_DIR and 'sudo' is not available."
    fi
fi

# --- 5. Verify & Finish ---
if ! command -v "$BIN_NAME" >/dev/null 2>&1; then
     log_error "Installation failed. '$BIN_NAME' is not in your PATH."
fi

INSTALLED_VERSION=$("$BIN_NAME" --version)
log_success "Successfully installed: $INSTALLED_VERSION"
echo ""
echo "Try it out by running:"
echo "  keeper start"
