#!/usr/bin/env bash
# ============================================================================
# KLCDS — Setup Script for Ubuntu 22.04 / 24.04 LTS
# ============================================================================
# Run as root inside your isolated VM:
#   sudo bash setup.sh
#
# This script:
#  1. Installs OS packages (eBPF tooling, ClamAV, nftables, auditd, etc.)
#  2. Creates the klcds system user & directories
#  3. Sets up a Python virtual environment
#  4. Installs the klcds package
#  5. Initializes the database
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║   ██╗  ██╗██╗      ██████╗██████╗ ███████╗                ║"
    echo "║   ██║ ██╔╝██║     ██╔════╝██╔══██╗██╔════╝                ║"
    echo "║   █████╔╝ ██║     ██║     ██║  ██║███████╗                ║"
    echo "║   ██╔═██╗ ██║     ██║     ██║  ██║╚════██║                ║"
    echo "║   ██║  ██╗███████╗╚██████╗██████╔╝███████║                ║"
    echo "║   ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═════╝ ╚══════╝                ║"
    echo "║                                                            ║"
    echo "║   Kernel-Level Cyber Defense System — Setup                ║"
    echo "║                                                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

step() {
    echo -e "\n${GREEN}[✓]${NC} ${BOLD}$1${NC}"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
    exit 1
}

# ---------- Pre-flight checks ----------

banner

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root.  Use: sudo bash setup.sh"
fi

# Check Ubuntu version
if ! grep -qE "22\.04|24\.04" /etc/os-release 2>/dev/null; then
    warn "This script is designed for Ubuntu 22.04/24.04 LTS."
    warn "Proceeding anyway, but some packages may differ."
fi

KLCDS_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="/var/lib/klcds"
LOG_DIR="/var/log/klcds"
CONF_DIR="/etc/klcds"
RUN_DIR="/var/run/klcds"
VENV_DIR="${KLCDS_DIR}/venv"

# ---------- Step 1: System packages ----------

step "Installing system packages..."

apt-get update -qq

apt-get install -y -qq \
    python3.11 python3.11-venv python3.11-dev python3-pip \
    build-essential \
    linux-headers-$(uname -r) \
    bpfcc-tools libbpf-dev bpftrace \
    clang llvm \
    clamav clamav-daemon \
    nftables \
    auditd audispd-plugins \
    nmap \
    sqlite3 \
    jq curl wget \
    libssl-dev \
    2>/dev/null || true

step "System packages installed."

# ---------- Step 2: ClamAV database update ----------

step "Updating ClamAV virus definitions..."
systemctl stop clamav-freshclam 2>/dev/null || true
freshclam --quiet 2>/dev/null || warn "ClamAV update failed (non-critical; may need proxy)"
systemctl start clamav-freshclam 2>/dev/null || true

# ---------- Step 3: Create directories ----------

step "Creating KLCDS directories..."

mkdir -p "${DATA_DIR}"
mkdir -p "${DATA_DIR}/quarantine"
mkdir -p "${DATA_DIR}/canary"
mkdir -p "${DATA_DIR}/backups"
mkdir -p "${DATA_DIR}/models"
mkdir -p "${LOG_DIR}"
mkdir -p "${CONF_DIR}/rules"
mkdir -p "${CONF_DIR}/rules.d"
mkdir -p "${CONF_DIR}/yara"
mkdir -p "${RUN_DIR}"

# Quarantine directory: root-only, chmod 000 at rest
chmod 700 "${DATA_DIR}/quarantine"

step "Directories created."

# ---------- Step 4: Copy config & rules ----------

step "Installing default configuration..."

if [[ ! -f "${CONF_DIR}/klcds.yaml" ]]; then
    cp "${KLCDS_DIR}/klcds.yaml" "${CONF_DIR}/klcds.yaml"
    echo "  Installed /etc/klcds/klcds.yaml"
else
    echo "  Config already exists; skipping."
fi

if [[ -d "${KLCDS_DIR}/rules" ]]; then
    cp -n "${KLCDS_DIR}/rules/"*.yaml "${CONF_DIR}/rules/" 2>/dev/null || true
    echo "  Installed detection rules to /etc/klcds/rules/"
fi

if [[ -d "${KLCDS_DIR}/yara" ]]; then
    cp -n "${KLCDS_DIR}/yara/"*.yar "${CONF_DIR}/yara/" 2>/dev/null || true
    echo "  Installed YARA rules to /etc/klcds/yara/"
fi

# ---------- Step 5: Python virtual environment ----------

step "Setting up Python virtual environment..."

python3.11 -m venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"
pip install --upgrade pip setuptools wheel -q
pip install -e "${KLCDS_DIR}" -q
pip install -r "${KLCDS_DIR}/requirements-dev.txt" -q 2>/dev/null || true

step "Python environment ready: ${VENV_DIR}"

# ---------- Step 6: Initialize database ----------

step "Initializing database..."

klcds init-db

# ---------- Step 7: Enable auditd ----------

step "Configuring auditd..."

systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true

# ---------- Step 8: nftables base table ----------

step "Creating nftables blocking table..."

nft add table inet klcds_block 2>/dev/null || true
nft add chain inet klcds_block klcds_input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true
nft add chain inet klcds_block klcds_output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true

step "nftables table 'klcds_block' ready."

# ---------- Done ----------

echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}  ${GREEN}Setup complete!${NC}                                            ${CYAN}║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}                                                            ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Activate the venv:                                        ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    source ${VENV_DIR}/bin/activate                     ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}                                                            ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Quick commands:                                           ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    klcds status          — system overview                 ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    klcds events          — recent events                   ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    klcds alerts          — recent alerts                   ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    klcds posture         — security score                  ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    klcds run             — start engine (safe mode)        ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    klcds run --enforce   — start with enforcement ⚠️       ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}                                                            ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo
