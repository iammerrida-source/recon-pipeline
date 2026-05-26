#!/usr/bin/env bash
# ══════════════════════════════════════════════════════
#  install.sh — Recon Pipeline Dependency Installer
#  Supports: Ubuntu/Debian, Arch, macOS
# ══════════════════════════════════════════════════════

set -euo pipefail

G='\033[0;32m' Y='\033[1;33m' R='\033[0;31m' C='\033[0;36m'
BOLD='\033[1m' NC='\033[0m'

ok()   { echo -e "${G}[✔]${NC} $1"; }
info() { echo -e "${C}[→]${NC} $1"; }
warn() { echo -e "${Y}[!]${NC} $1"; }
err()  { echo -e "${R}[✗]${NC} $1"; }
has()  { command -v "$1" &>/dev/null; }

TOOLS_DIR="${HOME}/tools"
WORDLIST_DIR="${TOOLS_DIR}/wordlists"
GO_TOOLS_DIR="${HOME}/go/bin"

echo -e "${C}${BOLD}"
cat << 'BANNER'
  ┌─────────────────────────────────────────────┐
  │   Recon Pipeline — Dependency Installer     │
  └─────────────────────────────────────────────┘
BANNER
echo -e "${NC}"

mkdir -p "$TOOLS_DIR" "$WORDLIST_DIR"

# ─── Detect OS ───────────────────────────────────────
OS=""
if [[ "$OSTYPE" == "darwin"* ]]; then
  OS="macos"
elif [[ -f /etc/debian_version ]]; then
  OS="debian"
elif [[ -f /etc/arch-release ]]; then
  OS="arch"
else
  OS="unknown"
fi
info "Detected OS: $OS"

# ─── Go ──────────────────────────────────────────────
install_go() {
  if has go; then
    ok "Go already installed: $(go version)"
    return
  fi
  info "Installing Go ..."
  GO_VERSION="1.22.3"
  case "$OS" in
    macos)
      if has brew; then
        brew install go
      else
        warn "Install Homebrew first: https://brew.sh"
        exit 1
      fi
      ;;
    debian)
      sudo apt-get install -y golang-go 2>/dev/null || \
      { # fallback به official release
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
      }
      ;;
    arch)
      sudo pacman -S --noconfirm go
      ;;
    *)
      warn "Unknown OS — install Go manually: https://go.dev/dl/"
      exit 1
      ;;
  esac
  ok "Go installed"
}

install_go

# ensure Go bin در PATH هست
export PATH="${PATH}:${GO_TOOLS_DIR}:${HOME}/go/bin"
if ! grep -q 'go/bin' ~/.bashrc 2>/dev/null; then
  echo 'export PATH="${PATH}:${HOME}/go/bin"' >> ~/.bashrc
fi

# ─── System packages ─────────────────────────────────
info "Installing system dependencies ..."
case "$OS" in
  debian)
    sudo apt-get update -qq
    sudo apt-get install -y -qq curl wget git python3 python3-pip jq dnsutils 2>/dev/null || true
    ;;
  arch)
    sudo pacman -S --noconfirm curl wget git python python-pip jq bind 2>/dev/null || true
    ;;
  macos)
    has brew && brew install curl wget git python3 jq 2>/dev/null || true
    ;;
esac

# ─── Go tools ────────────────────────────────────────
install_go_tool() {
  local name="$1"
  local pkg="$2"
  if has "$name"; then
    ok "$name already installed"
  else
    info "Installing $name ..."
    go install "${pkg}@latest" 2>/dev/null && ok "$name installed" || \
      warn "Failed to install $name — skipping"
  fi
}

echo ""
info "Installing required Go tools ..."
install_go_tool subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool dnsx        "github.com/projectdiscovery/dnsx/cmd/dnsx"
install_go_tool shuffledns  "github.com/projectdiscovery/shuffledns/cmd/shuffledns"
install_go_tool httpx       "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool alterx      "github.com/projectdiscovery/alterx/cmd/alterx"

echo ""
info "Installing optional Go tools ..."
install_go_tool asnmap            "github.com/projectdiscovery/asnmap/cmd/asnmap"
install_go_tool tlsx              "github.com/projectdiscovery/tlsx/cmd/tlsx"
install_go_tool github-subdomains "github.com/gwen001/github-subdomains"
install_go_tool chaos             "github.com/projectdiscovery/chaos-client/cmd/chaos"

# amass (جدا چون سنگینه)
if ! has amass; then
  info "Installing amass ..."
  go install github.com/owasp-amass/amass/v4/...@master 2>/dev/null && \
    ok "amass installed" || warn "amass install failed — skipping (optional)"
fi

# dnsvalidator
if ! has dnsvalidator; then
  info "Installing dnsvalidator ..."
  pip3 install dnsvalidator --quiet 2>/dev/null && \
    ok "dnsvalidator installed" || warn "dnsvalidator install failed — skipping (optional)"
fi

# s3scanner
if ! has s3scanner; then
  info "Installing s3scanner ..."
  pip3 install s3scanner --quiet 2>/dev/null && \
    ok "s3scanner installed" || warn "s3scanner install failed — skipping (optional)"
fi

# ─── Wordlist ─────────────────────────────────────────
echo ""
info "Setting up wordlists ..."

JHADDIX="$WORDLIST_DIR/all.txt"
if [[ -f "$JHADDIX" ]]; then
  ok "jhaddix all.txt already exists ($(wc -l < "$JHADDIX" | tr -d ' ') lines)"
else
  info "Downloading jhaddix all.txt ..."
  wget -q --show-progress \
    "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/all.txt" \
    -O "$JHADDIX" && ok "Wordlist downloaded: $JHADDIX" || \
    warn "Failed to download wordlist — provide manually at $JHADDIX"
fi

# ─── Resolvers ────────────────────────────────────────
RESOLVERS_FILE="${TOOLS_DIR}/resolvers.txt"
if [[ -f "$RESOLVERS_FILE" ]]; then
  ok "resolvers.txt already exists ($(wc -l < "$RESOLVERS_FILE" | tr -d ' ') resolvers)"
else
  info "Downloading resolvers list ..."
  wget -q --show-progress \
    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
    -O "$RESOLVERS_FILE" && ok "Resolvers downloaded: $RESOLVERS_FILE" || \
    warn "Failed to download resolvers — provide manually at $RESOLVERS_FILE"
fi

# ─── Permissions ──────────────────────────────────────
chmod +x recon_pipeline.sh 2>/dev/null || true

# ─── Summary ──────────────────────────────────────────
echo ""
echo -e "${G}${BOLD}══════════════════════════════════════${NC}"
echo -e "${G}${BOLD}  Installation complete!${NC}"
echo -e "${G}${BOLD}══════════════════════════════════════${NC}"
echo ""
echo -e "  Wordlist  : ${C}$JHADDIX${NC}"
echo -e "  Resolvers : ${C}$RESOLVERS_FILE${NC}"
echo ""
echo -e "  Run: ${BOLD}./recon_pipeline.sh -d example.com${NC}"
echo ""

# final tool check
echo -e "${Y}Tool availability:${NC}"
for t in subfinder dnsx shuffledns httpx alterx asnmap tlsx amass chaos \
          github-subdomains dnsvalidator s3scanner jq; do
  has "$t" && echo -e "  ${G}✔${NC} $t" || echo -e "  ${Y}✗${NC} $t (optional)"
done
echo ""
