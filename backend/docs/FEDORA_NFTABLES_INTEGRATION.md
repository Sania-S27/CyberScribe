# CyberScribe — Fedora 44 nftables Executor Integration Guide

## 1. Overview & Architecture

CyberScribe integrates with a dedicated Fedora 44 virtual machine running in VirtualBox to execute real, narrowly scoped packet-dropping rules using `nftables`.

### Key Design Principles:
- **Default Safety (Simulation First)**: CyberScribe defaults to `CONTAINMENT_ADAPTER_MODE="simulated"`. The live Fedora adapter is only active when explicitly configured.
- **Dedicated nftables Table**: All CyberScribe rules live exclusively in table `inet cyberscribe`. Fedora's existing `firewalld` configuration and system rules are **never touched or flushed**.
- **Enforceable Least-Privilege Boundary**:
  - The unprivileged daemon user `cyberscribe` has **NO** sudo access to `/usr/sbin/nft`.
  - Sudoers strictly authorizes execution of a fixed, root-owned helper script: `/usr/libexec/cyberscribe/cyberscribe_nft_helper.py`.
  - The helper script exposes only fixed, parameterized operations (`init`, `apply`, `verify`, `delete-handle`, `rollback`, `list`).
  - The helper script re-validates all inputs, restricts actions strictly to `table inet cyberscribe`, and refuses to execute arbitrary nftables commands or modify default policies.
- **Atomic Application & Partial-Failure Rollback**: Multi-rule insertions (inbound and outbound) are tracked. If adding an inbound rule fails after outbound succeeds, staged rules are immediately rolled back to prevent half-applied state.
- **Exact Ownership & Handle Verification**: Every rule is tagged with `comment "cyberscribe:<action_id>"`. Rule deletion verifies that the rule handle belongs to that exact `action_id` before deletion. Unrelated rules cannot be deleted.
- **Constant-Time Authentication**: Every request requires a high-entropy secret token passed via `Authorization: Bearer <TOKEN>` and validated via `hmac.compare_digest`.
- **Bounded Resources**: Request size is limited to 64KB with strict timeouts (8–10s).

```
┌─────────────────────────────────┐                 ┌──────────────────────────────────────────────────┐
│       Host (CyberScribe)        │                 │               Fedora 44 VirtualBox               │
│                                 │                 │                                                  │
│  Autonomous Containment Policy  │                 │  VirtualBox NAT Port Forward: 127.0.0.1:8088     │
│                │                │  HTTP POST/GET  │                         │                        │
│                ▼                │ ──────────────> │            cyberscribe-executor daemon           │
│      FedoraNftablesAdapter      │  Bearer Auth    │              (User: cyberscribe)                 │
│        (Live Lifecycle)         │                 │                         │                        │
│                                 │                 │                         ▼ sudo (restricted)      │
│                                 │                 │      /usr/libexec/cyberscribe_nft_helper.py      │
│                                 │                 │            (Root-owned, locked-down)             │
│                                 │                 │                         │                        │
│                                 │                 │                         ▼ tokenized /usr/sbin/nft│
│                                 │                 │            Table: `inet cyberscribe`             │
│                                 │                 │          Chain: `inbound_filter` (-5)            │
│                                 │                 │          Chain: `outbound_filter` (-5)           │
│                                 │                 │            [firewalld remains untouched]         │
└─────────────────────────────────┘                 └──────────────────────────────────────────────────┘
```

---

## 2. Network Isolation & VirtualBox NAT Configuration

Both the VM and host remain completely private; neither service is exposed to the local network or internet.

### VirtualBox NAT Port Forwarding Rules
In VirtualBox Manager, configure two port-forwarding rules on the Fedora VM's **Adapter 1 (NAT)**:

1. Open VirtualBox Manager $\to$ Select **Fedora 44 VM** $\to$ **Settings** $\to$ **Network** $\to$ **Adapter 1**.
2. Confirm **Attached to:** is set to **NAT**.
3. Expand **Advanced** $\to$ Click **Port Forwarding**.
4. Configure the following rules:

| Rule Name | Protocol | Host IP | Host Port | Guest IP | Guest Port | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `CyberScribe-SSH` | TCP | `127.0.0.1` | `2222` | *(blank)* | `22` | Private admin/transfer (avoids port 22 conflict) |
| `CyberScribe-Executor` | TCP | `127.0.0.1` | `8088` | *(blank)* | `8088` | Isolated HTTP API for containment engine |

> [!IMPORTANT]
> Specifying Host IP as `127.0.0.1` ensures that port 2222 and port 8088 are only accessible locally on your Windows development machine, and are **never exposed publicly**.

---

## 3. Verified Transfer and Installation Procedure

### Prerequisites on Fedora 44 Guest:
1. Ensure OpenSSH server is running inside the VM:
   ```bash
   sudo systemctl enable --now sshd
   ```
2. Verify the VirtualBox NAT port-forwarding rules from Section 2 are active.

### Step 3.1: Transfer the Bundle from Windows Host to Fedora VM
From your Windows host PowerShell in the project root:
```powershell
# Transfer deployment files to /tmp/ on the Fedora guest via port 2222
scp -P 2222 -r .\backend\scripts\fedora_executor <fedora_user>@127.0.0.1:/tmp/
```
*(Replace `<fedora_user>` with your non-root Fedora user account).*

### Step 3.2: Run the Installer on Fedora
SSH into the VM via port 2222 and run the installer:
```powershell
ssh -p 2222 <fedora_user>@127.0.0.1
```
Inside the Fedora terminal:
```bash
sudo chmod +x /tmp/fedora_executor/install_fedora_executor.sh
sudo /tmp/fedora_executor/install_fedora_executor.sh
```

The installer script automatically:
1. Installs `nftables` and `python3` if missing.
2. Creates the non-login system user `cyberscribe`.
3. Deploys the root-owned helper `/usr/libexec/cyberscribe/cyberscribe_nft_helper.py` (`chmod 755`, `chown root:root`).
4. Configures `/etc/sudoers.d/cyberscribe-nftables` allowing `cyberscribe` to run **only** `/usr/libexec/cyberscribe/cyberscribe_nft_helper.py` (and verifies syntax with `visudo`).
5. Deploys `/opt/cyberscribe-executor/executor_daemon.py` (`chown cyberscribe:cyberscribe`, `chmod 750`).
6. Generates a cryptographically random 32-byte secret in `/etc/cyberscribe-executor.env` (`chmod 600`, `chown root:cyberscribe`).
7. Installs and starts `cyberscribe-executor.service`.

### Step 3.3: Retrieve Authentication Secret
Inside the VM, display the generated secret:
```bash
sudo cat /etc/cyberscribe-executor.env
```
Copy the `FEDORA_EXECUTOR_TOKEN` value for host configuration.

---

## 4. CyberScribe Host Configuration

In `backend/.env` on the Windows host:

```ini
# Explicitly enable live Fedora 44 nftables execution
CONTAINMENT_ADAPTER_MODE="fedora_nftables"

# Fedora Executor Endpoint (via VirtualBox NAT port-forward)
FEDORA_EXECUTOR_URL="http://127.0.0.1:8088"

# High-entropy token from /etc/cyberscribe-executor.env
FEDORA_EXECUTOR_TOKEN="<PASTE_FEDORA_TOKEN_HERE>"

# Dedicated table name
FEDORA_NFTABLES_TABLE="cyberscribe"
```

To revert back to simulation mode at any time, simply set:
```ini
CONTAINMENT_ADAPTER_MODE="simulated"
```

---

## 5. Inspecting & Managing Live nftables Rules

### 5.1: View Managed Rules on Fedora
```bash
sudo nft -a list table inet cyberscribe
```
Output displays the isolated table, priority -5 filter chains, and rule comments:
```text
table inet cyberscribe {
    chain inbound_filter {
        type filter hook input priority -5; policy accept;
        ip saddr 185.220.101.5 drop comment "cyberscribe:act-auto-a1b2c3d4e5f6" # handle 2
    }
    chain outbound_filter {
        type filter hook output priority -5; policy accept;
        ip daddr 185.220.101.5 drop comment "cyberscribe:act-auto-a1b2c3d4e5f6" # handle 3
    }
}
```

### 5.2: Rollback via CyberScribe API or Host Endpoint
Using CyberScribe's tenant rollback endpoint:
```http
POST /api/tenants/containment/actions/{action_id}/rollback
Authorization: Bearer <TENANT_JWT_TOKEN>
```

Or via direct HTTP call to the executor:
```bash
curl -X POST http://127.0.0.1:8088/rollback/act-auto-a1b2c3d4e5f6 \
     -H "Authorization: Bearer <FEDORA_EXECUTOR_TOKEN>"
```

### 5.3: Verify firewalld Is Untouched
```bash
sudo firewall-cmd --state
sudo firewall-cmd --list-all
```
Fedora's firewalld zones, services, and default policies remain completely separate and undisturbed.

---

## 6. Behavior When the VM Is Offline or Unreachable

- **Honest Failure**: If the Fedora VM is powered down, suspended, or network connectivity fails:
  - CyberScribe **never** marks actions as `APPLIED` or `VERIFIED`.
  - The action status transitions to `FAILED`.
  - The exact network error (`Connection refused`, `timeout`) is recorded in `error_message` and logged to `_containment_audit_logs`.
- **Expiry When VM is Unavailable**:
  - `check_and_expire` attempts host-level rule removal. If unreachable, the failure is recorded honestly without pretending the rule was removed.
- **Rollback When VM is Unavailable**:
  - Rollback requires verified rule removal. If unreachable, the rollback raises an error and preserves the un-rolled-back state until connectivity is restored.

---

## 7. How to Disable the Executor Safely

1. Set `CONTAINMENT_ADAPTER_MODE="simulated"` in `backend/.env`.
2. To remove all CyberScribe rules on the Fedora VM:
   ```bash
   sudo nft delete table inet cyberscribe
   ```
3. Stop and disable the systemd service on Fedora:
   ```bash
   sudo systemctl stop cyberscribe-executor.service
   sudo systemctl disable cyberscribe-executor.service
   ```
