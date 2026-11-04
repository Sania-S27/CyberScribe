#!/usr/bin/env bash
# ==============================================================================
# CyberScribe Fedora 44 nftables Executor Installation Script
# Run as root or with sudo inside the Fedora 44 VM.
# ==============================================================================

set -euo pipefail

echo "================================================================================"
echo "Installing CyberScribe nftables Executor Service on Fedora 44"
echo "================================================================================"

# 1. Verify nftables and python3 are installed
if ! command -v nft >/dev/null 2>&1; then
    echo "[*] Installing nftables package..."
    dnf install -y nftables
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "[*] Installing python3..."
    dnf install -y python3
fi

# 2. Create service account
if ! id -u cyberscribe >/dev/null 2>&1; then
    echo "[*] Creating dedicated system user 'cyberscribe'..."
    useradd --system --shell /sbin/nologin --comment "CyberScribe Containment Executor" cyberscribe
fi

# 3. Install privileged helper (Owned by root, executable by cyberscribe via sudo)
HELPER_DIR="/usr/libexec/cyberscribe"
echo "[*] Installing privileged helper to ${HELPER_DIR}..."
mkdir -p "${HELPER_DIR}"
cp "$(dirname "$0")/cyberscribe_nft_helper.py" "${HELPER_DIR}/cyberscribe_nft_helper.py"
chown root:root "${HELPER_DIR}/cyberscribe_nft_helper.py"
chmod 755 "${HELPER_DIR}/cyberscribe_nft_helper.py"

# 4. Install restricted sudoers policy (Permits ONLY the helper, NOT /usr/sbin/nft)
echo "[*] Installing restricted sudoers policy..."
cp "$(dirname "$0")/cyberscribe-nftables.sudoers" /etc/sudoers.d/cyberscribe-nftables
chmod 440 /etc/sudoers.d/cyberscribe-nftables
chown root:root /etc/sudoers.d/cyberscribe-nftables

# Validate sudoers configuration
visudo -c -f /etc/sudoers.d/cyberscribe-nftables

# 5. Create deployment directory for unprivileged daemon
INSTALL_DIR="/opt/cyberscribe-executor"
echo "[*] Installing daemon files to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
cp "$(dirname "$0")/executor_daemon.py" "${INSTALL_DIR}/executor_daemon.py"
cp "$(dirname "$0")/cyberscribe_nft_helper.py" "${INSTALL_DIR}/cyberscribe_nft_helper.py"
chown -R cyberscribe:cyberscribe "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}/executor_daemon.py"
chmod 640 "${INSTALL_DIR}/cyberscribe_nft_helper.py"

# 6. Generate secure token if missing
ENV_FILE="/etc/cyberscribe-executor.env"
if [ ! -f "${ENV_FILE}" ]; then
    echo "[*] Generating high-entropy authentication token..."
    GEN_TOKEN=$(openssl rand -hex 32)
    cat <<EOF > "${ENV_FILE}"
# CyberScribe Executor Authentication Configuration
FEDORA_EXECUTOR_TOKEN=${GEN_TOKEN}
FEDORA_NFTABLES_TABLE=cyberscribe
FEDORA_EXECUTOR_HOST=0.0.0.0
FEDORA_EXECUTOR_PORT=8088
CYBERSCRIBE_NFT_HELPER_PATH=/usr/libexec/cyberscribe/cyberscribe_nft_helper.py
EOF
    chmod 600 "${ENV_FILE}"
    chown root:cyberscribe "${ENV_FILE}"
    echo "[!] Generated new token in ${ENV_FILE}"
    echo "================================================================================"
    echo "SAVE THIS TOKEN FOR CYBERSCRIBE .env (FEDORA_EXECUTOR_TOKEN):"
    echo "${GEN_TOKEN}"
    echo "================================================================================"
else
    echo "[OK] Existing environment file found at ${ENV_FILE}"
fi

# 7. Install systemd service
echo "[*] Installing systemd service..."
cp "$(dirname "$0")/cyberscribe-executor.service" /etc/systemd/system/cyberscribe-executor.service
systemctl daemon-reload
systemctl enable cyberscribe-executor.service
systemctl restart cyberscribe-executor.service

echo "[*] Checking service status..."
systemctl is-active --quiet cyberscribe-executor.service && echo "[SUCCESS] cyberscribe-executor is active and running on port 8088!" || echo "[WARNING] Service failed to start. Check: journalctl -u cyberscribe-executor"
