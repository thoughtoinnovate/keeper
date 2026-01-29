# 🚢 Document 7: CI/CD, Release Strategy & Installation (release.md)

This document outlines the strategy for setting up Continuous Integration (CI), automating releases, and providing a one-line installer for users.

### Goals
1.  **CI:** Run tests and lints on every commit.
2.  **CD:** Automatically cross-compile and publish binaries for Linux (x86/ARM), macOS (Intel/Silicon), and Windows on tag pushes.
3.  **Install:** Provide a simple script for users to detect their OS and download the correct binary.

---

### 1. CI/CD GitHub Actions Workflows

Create the directory `.github/workflows/` in the project root and add these three YAML files.

#### A. Continuous Integration (`.github/workflows/ci.yml`)
Triggers on pushes to main and PRs. Runs fmt check, clippy lint, and all tests.

```yaml
name: CI
on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]
env:
  CARGO_TERM_COLOR: always
jobs:
  test:
    name: Test Suite (Linux)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust Stable
        uses: dtolnay/rust-toolchain@stable
      - name: Rust Cache
        uses: Swatinem/rust-cache@v2
      - name: Check Formatting
        run: cargo fmt --all -- --check
      - name: Clippy Lint
        run: cargo clippy -- -D warnings
      - name: Run Tests
        run: cargo test
```

#### B. Documentation Builder (`.github/workflows/docs.yml`)
Triggers on pushes to main. Builds rustdoc and deploys to GitHub Pages. (Requires GitHub Pages source set to "GitHub Actions" in repo settings).

```yaml
name: Deploy Docs
on:
  push:
    branches: ["main"]
permissions:
  contents: read
  pages: write
  id-token: write
jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      - name: Build Documentation
        run: cargo doc --no-deps --document-private-items
      - name: Setup Pages
        uses: actions/configure-pages@v3
      - name: Upload artifact
        uses: actions/upload-pages-artifact@v2
        with:
          path: 'target/doc'
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v2
```

#### C. Release & Cross-Compile (`.github/workflows/release.yml`)
Triggers when a tag like `v0.1.0` is pushed. Uses a matrix to build on different OSs and `cross` for Raspberry Pi ARM builds.

```yaml
name: Release Binaries
on:
  push:
    tags:
      - 'v*'
permissions:
  contents: write
jobs:
  create-release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Create GitHub Release Draft
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh release create ${{ github.ref_name }} --draft --generate-notes --title "${{ github.ref_name }}"

  build-assets:
    name: Build release assets
    needs: create-release
    runs-on: ${{ matrix.config.os }}
    strategy:
      fail-fast: false
      matrix:
        config:
          - { os: ubuntu-latest, target: x86_64-unknown-linux-gnu, use_cross: false } # Linux x86
          - { os: ubuntu-latest, target: aarch64-unknown-linux-gnu, use_cross: true }  # Linux ARM64 (RPi)
          - { os: macos-latest, target: x86_64-apple-darwin, use_cross: false }       # Mac Intel
          - { os: macos-latest, target: aarch64-apple-darwin, use_cross: false }      # Mac Silicon
          - { os: windows-latest, target: x86_64-pc-windows-msvc, use_cross: false }  # Windows x86

    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.config.target }}
      - name: Build and Upload Asset
        uses: taiki-e/upload-rust-binary-action@v1
        with:
          bin: keeper
          target: ${{ matrix.config.target }}
          use-cross: ${{ matrix.config.use_cross }}
          token: ${{ secrets.GITHUB_TOKEN }}
          include: LICENSE, README.md 
```

---

### 2. The One-Line Installer Script

To allow users to install Keeper effortlessly with a command like `curl https://.../install.sh | sh`, create the following script.

1.  Create a file named `install.sh` in the root of your repository.
2.  **IMPORTANT:** Update the `REPO_URL` variable at the top of the script with your actual GitHub URL.
3.  Commit it to the repository.

```bash
#!/bin/sh
set -e

# =================================================================
#  KEEPER INSTALLATION SCRIPT
# =================================================================
#  TODO: REPLACE THIS WITH YOUR ACTUAL GITHUB REPO URL BEFORE COMMITTING
REPO_URL="[https://github.com/YOUR_USERNAME_HERE/keeper](https://github.com/YOUR_USERNAME_HERE/keeper)"
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
```