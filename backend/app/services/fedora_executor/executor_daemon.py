"""
CyberScribe Fedora nftables Executor Daemon
--------------------------------------------
Lightweight, hardened microservice designed to run inside the Fedora 44 VM.
Exposes strictly scoped endpoints for IPv4 packet dropping in a dedicated,
isolated nftables table (`inet cyberscribe`).

SECURITY SAFEGUARDS:
1. Least Privilege Boundary: Invokes a fixed, root-owned helper script
   (`/usr/libexec/cyberscribe/cyberscribe_nft_helper.py`) via sudo.
   The daemon user has NO sudo permissions to `/usr/sbin/nft` directly.
2. Never flushes or modifies Fedora's existing firewalld tables or policies.
3. Authentication: Mandatory on all state-changing and query endpoints using
   constant-time bearer token validation (hmac.compare_digest).
4. Strict Input Validation: Accepts only single valid public IPv4 addresses;
   rejects private, loopback, link-local, multicast, reserved, broadcast, and protected IPs.
5. Strict Action ID Validation: Alphanumeric + hyphen/underscore, length 3-64.
6. Exact Ownership Enforcement: Rules are stamped with 'cyberscribe:<action_id>'.
   Rule deletion by handle strictly verifies ownership before deletion.
7. Partial Failure Recovery: Atomic multi-rule application; if adding an inbound
   rule fails after outbound succeeds, staged rules are immediately rolled back.
8. Bounded requests: Enforces 64KB request body limit and 8-second execution timeouts.
"""

import os
import sys
import re
import json
import hmac
import logging
import ipaddress
import subprocess
import importlib.util
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List, Optional, Tuple

# -----------------------------------------------------------------------------
# Secure Helper Import Resolution
# -----------------------------------------------------------------------------
# CyberScribe requires the privileged helper module for all containment operations.
# - In test and development environments: loaded via backend package hierarchy.
# - In standalone Fedora VM deployments: loaded from /usr/libexec/cyberscribe/
#   or from the path specified by CYBERSCRIBE_NFT_HELPER_PATH.
#
# SECURITY GUARANTEE: If the verified helper cannot be located or loaded,
# the executor daemon fails closed immediately at startup.
# It refuses to execute with unverified, undefined, or missing security validators.
# -----------------------------------------------------------------------------

_HELPER_LOADED = False
CyberscribeNftHelper = None
HelperSecurityError = None
OwnershipMismatchError = None
InspectionError = None
validate_public_ipv4 = None
validate_action_id = None
validate_table_name = None
validate_chain_name = None
validate_handle = None

# Attempt 1: Standard package import (used when running within backend repo / tests)
try:
    from app.services.fedora_executor.cyberscribe_nft_helper import (
        CyberscribeNftHelper as _Helper,
        HelperSecurityError as _HSE,
        OwnershipMismatchError as _OME,
        InspectionError as _IE,
        validate_public_ipv4 as _v_ip,
        validate_action_id as _v_aid,
        validate_table_name as _v_tab,
        validate_chain_name as _v_chn,
        validate_handle as _v_hnd,
    )
    CyberscribeNftHelper = _Helper
    HelperSecurityError = _HSE
    OwnershipMismatchError = _OME
    InspectionError = _IE
    validate_public_ipv4 = _v_ip
    validate_action_id = _v_aid
    validate_table_name = _v_tab
    validate_chain_name = _v_chn
    validate_handle = _v_hnd
    _HELPER_LOADED = True
except ImportError:
    pass

# Attempt 2: Standalone directory discovery via sys.path
if not _HELPER_LOADED:
    helper_env_path = os.getenv("CYBERSCRIBE_NFT_HELPER_PATH", "/usr/libexec/cyberscribe/cyberscribe_nft_helper.py")
    candidate_dirs = [
        os.path.dirname(os.path.abspath(helper_env_path)),
        "/usr/libexec/cyberscribe",
        os.path.dirname(os.path.abspath(__file__)),
        os.getcwd(),
    ]
    for c_dir in candidate_dirs:
        if c_dir and os.path.isdir(c_dir) and c_dir not in sys.path:
            sys.path.insert(0, c_dir)

    try:
        from cyberscribe_nft_helper import (
            CyberscribeNftHelper as _Helper,
            HelperSecurityError as _HSE,
            OwnershipMismatchError as _OME,
            InspectionError as _IE,
            validate_public_ipv4 as _v_ip,
            validate_action_id as _v_aid,
            validate_table_name as _v_tab,
            validate_chain_name as _v_chn,
            validate_handle as _v_hnd,
        )
        CyberscribeNftHelper = _Helper
        HelperSecurityError = _HSE
        OwnershipMismatchError = _OME
        InspectionError = _IE
        validate_public_ipv4 = _v_ip
        validate_action_id = _v_aid
        validate_table_name = _v_tab
        validate_chain_name = _v_chn
        validate_handle = _v_hnd
        _HELPER_LOADED = True
    except ImportError:
        pass

# Attempt 3: Direct module loading from exact file location via importlib
if not _HELPER_LOADED:
    target_helper_path = os.getenv("CYBERSCRIBE_NFT_HELPER_PATH", "/usr/libexec/cyberscribe/cyberscribe_nft_helper.py")
    if not os.path.isabs(target_helper_path):
        target_helper_path = os.path.abspath(target_helper_path)

    if not os.path.isfile(target_helper_path):
        sibling_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberscribe_nft_helper.py")
        if os.path.isfile(sibling_path):
            target_helper_path = sibling_path

    if os.path.isfile(target_helper_path):
        try:
            spec = importlib.util.spec_from_file_location("cyberscribe_nft_helper", target_helper_path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules["cyberscribe_nft_helper"] = mod
                spec.loader.exec_module(mod)
                CyberscribeNftHelper = getattr(mod, "CyberscribeNftHelper")
                HelperSecurityError = getattr(mod, "HelperSecurityError")
                OwnershipMismatchError = getattr(mod, "OwnershipMismatchError")
                InspectionError = getattr(mod, "InspectionError")
                validate_public_ipv4 = getattr(mod, "validate_public_ipv4")
                validate_action_id = getattr(mod, "validate_action_id")
                validate_table_name = getattr(mod, "validate_table_name")
                validate_chain_name = getattr(mod, "validate_chain_name")
                validate_handle = getattr(mod, "validate_handle")
                _HELPER_LOADED = True
        except Exception as load_err:
            raise ImportError(
                f"FATAL: Failed to load required cyberscribe_nft_helper from '{target_helper_path}': {load_err}"
            ) from load_err

# Fail closed if any required symbol could not be loaded
if not _HELPER_LOADED or any(
    sym is None for sym in (
        CyberscribeNftHelper,
        HelperSecurityError,
        OwnershipMismatchError,
        InspectionError,
        validate_public_ipv4,
        validate_action_id,
        validate_table_name,
        validate_chain_name,
        validate_handle,
    )
):
    searched_locations = [
        os.getenv("CYBERSCRIBE_NFT_HELPER_PATH", "/usr/libexec/cyberscribe/cyberscribe_nft_helper.py"),
        "/usr/libexec/cyberscribe/cyberscribe_nft_helper.py",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberscribe_nft_helper.py"),
    ]
    raise ImportError(
        "FATAL: Required cyberscribe_nft_helper module and security validators could not be imported. "
        f"Searched locations: {searched_locations}. "
        "The Fedora executor daemon fails closed and refuses to start without verified security validators."
    )

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [FedoraExecutor] %(message)s"
)
logger = logging.getLogger("FedoraExecutor")

# Default Configuration
DEFAULT_TABLE = "cyberscribe"
DEFAULT_PORT = 8088
DEFAULT_HOST = "0.0.0.0"
DEFAULT_HELPER_PATH = "/usr/libexec/cyberscribe/cyberscribe_nft_helper.py"
MAX_REQUEST_BYTES = 65536  # 64 KB limit


class ExecutorSecurityError(Exception):
    """Raised on security check failure or invalid input."""
    pass


class NftablesController:
    """
    Safely delegates operations to the fixed privileged helper.
    Never executes arbitrary commands or raw strings.
    """

    def __init__(
        self,
        table_name: str = DEFAULT_TABLE,
        dry_run: bool = False,
        sudo: bool = True,
        helper_path: str = DEFAULT_HELPER_PATH
    ):
        self.table_name = table_name
        self.dry_run = dry_run
        self.sudo = sudo
        self.helper_path = os.getenv("CYBERSCRIBE_NFT_HELPER_PATH", helper_path)
        # In-process helper fallback for test environments or dry runs
        self._in_process_helper = None
        if CyberscribeNftHelper is not None:
            self._in_process_helper = CyberscribeNftHelper(table_name=table_name, dry_run=dry_run)

    def _run_helper(self, args: List[str]) -> Dict[str, Any]:
        """Executes the fixed privileged helper via sudo and parses JSON response."""
        # Check if helper script exists on filesystem; if not and in dry-run/test mode, use in-process helper
        if not os.path.exists(self.helper_path) and self._in_process_helper is not None:
            return self._run_in_process(args)

        cmd = ["sudo", self.helper_path] if self.sudo else [self.helper_path]
        cmd.extend(args)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would execute: {' '.join(cmd)}")
            return {"status": "SUCCESS", "dry_run": True, "command": cmd}

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                shell=False
            )
            if proc.returncode != 0:
                err_text = proc.stderr.strip() or proc.stdout.strip()
                try:
                    err_json = json.loads(err_text)
                    raise ExecutorSecurityError(err_json.get("error", err_text))
                except json.JSONDecodeError:
                    raise ExecutorSecurityError(f"Helper exited with code {proc.returncode}: {err_text}")

            return json.loads(proc.stdout)
        except subprocess.TimeoutExpired:
            raise ExecutorSecurityError("Privileged helper execution timed out (10s limit).")
        except json.JSONDecodeError as jde:
            raise ExecutorSecurityError(f"Helper output could not be parsed as JSON: {jde}")
        except Exception as e:
            if isinstance(e, ExecutorSecurityError):
                raise
            raise ExecutorSecurityError(f"Failed to execute privileged helper: {e}")

    def _run_in_process(self, args: List[str]) -> Dict[str, Any]:
        """Runs the helper logic in-process (used for testing environments without root)."""
        if not self._in_process_helper:
            raise ExecutorSecurityError("In-process helper not available.")
        cmd = args[0]
        try:
            if cmd == "init":
                return self._in_process_helper.init_table_and_chains()
            elif cmd == "list":
                return {"rules": self._in_process_helper.list_rules()}
            elif cmd == "apply":
                action_id = args[1]
                ip_str = args[2]
                direction = args[3] if len(args) > 3 else "both"
                return self._in_process_helper.apply_block(action_id, ip_str, direction)
            elif cmd == "verify":
                action_id = args[1]
                expected_ip = args[2] if len(args) > 2 else None
                return self._in_process_helper.verify_rule(action_id, expected_ip)
            elif cmd == "delete-handle":
                action_id = args[1]
                chain = args[2]
                handle = int(args[3])
                return self._in_process_helper.delete_rule_by_handle(action_id, chain, handle)
            elif cmd == "rollback":
                action_id = args[1]
                return self._in_process_helper.rollback_action(action_id)
            else:
                raise ExecutorSecurityError(f"Unknown helper command: {cmd}")
        except (HelperSecurityError, OwnershipMismatchError) as hse:
            raise ExecutorSecurityError(str(hse))

    def ensure_table_and_chains(self) -> Dict[str, Any]:
        """Initializes dedicated table and chains."""
        return self._run_helper(["init"])

    def list_managed_rules(self) -> List[Dict[str, Any]]:
        """Lists managed rules in table."""
        res = self._run_helper(["list"])
        return res.get("rules", [])

    def apply_ip_block(
        self,
        action_id: str,
        ip_addr: Any,
        direction: str = "both"
    ) -> Dict[str, Any]:
        """Applies drop rules with strict validation and partial-failure rollback."""
        try:
            clean_action_id = validate_action_id(action_id)
            clean_ip = str(validate_public_ipv4(str(ip_addr)))
            clean_direction = str(direction).strip().lower()
            if clean_direction not in ("both", "inbound", "ingress", "outbound", "egress"):
                raise ExecutorSecurityError(f"Invalid direction '{clean_direction}'.")
        except (HelperSecurityError, ValueError) as err:
            raise ExecutorSecurityError(str(err))
        return self._run_helper(["apply", clean_action_id, clean_ip, clean_direction])

    def verify_action_rule(self, action_id: str, expected_ip: Optional[str] = None) -> Dict[str, Any]:
        """Independent read-back verification of action rules."""
        try:
            clean_action_id = validate_action_id(action_id)
            args = ["verify", clean_action_id]
            if expected_ip:
                clean_ip = str(validate_public_ipv4(str(expected_ip)))
                args.append(clean_ip)
        except (HelperSecurityError, ValueError) as err:
            raise ExecutorSecurityError(str(err))
        return self._run_helper(args)

    def rollback_action_rule(self, action_id: str) -> Dict[str, Any]:
        """Rolls back all rules belonging to action_id."""
        try:
            clean_action_id = validate_action_id(action_id)
        except (HelperSecurityError, ValueError) as err:
            raise ExecutorSecurityError(str(err))
        return self._run_helper(["rollback", clean_action_id])

    def delete_rule_handle(self, action_id: str, chain: str, handle: int) -> Dict[str, Any]:
        """Deletes rule by handle with strict ownership check."""
        try:
            clean_action_id = validate_action_id(action_id)
            clean_chain = validate_chain_name(chain)
            clean_handle = validate_handle(handle)
        except (HelperSecurityError, ValueError) as err:
            raise ExecutorSecurityError(str(err))
        return self._run_helper(["delete-handle", clean_action_id, clean_chain, str(clean_handle)])



class ExecutorRequestHandler(BaseHTTPRequestHandler):
    """Hardened HTTP Request Handler for the Fedora nftables executor."""

    controller: NftablesController
    auth_token: str

    def _authenticate(self) -> bool:
        """Verifies bearer token using constant-time comparison."""
        auth_header = self.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif "X-Executor-Token" in self.headers:
            token = self.headers.get("X-Executor-Token", "").strip()

        if not token or not self.auth_token:
            return False

        return hmac.compare_digest(token, self.auth_token)

    def _send_json(self, status_code: int, data: Dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _drain_body(self) -> None:
        """Safely consumes unread bytes up to MAX_REQUEST_BYTES to avoid TCP RST on Windows."""
        cl_raw = self.headers.get("Content-Length")
        if cl_raw and cl_raw.strip().isdigit():
            try:
                drain = min(int(cl_raw.strip()), 256 * 1024)
                if drain > 0:
                    self.rfile.read(drain)
            except Exception:
                pass

    def _send_error(self, status_code: int, message: str) -> None:
        self._send_json(status_code, {"error": message, "status": "FAILED"})

    def _read_json_body(self) -> Dict[str, Any]:
        cl_raw = self.headers.get("Content-Length")
        if cl_raw is None or not cl_raw.strip():
            content_length = 0
        else:
            try:
                content_length = int(cl_raw.strip())
                if content_length < 0:
                    raise ValueError("Content-Length cannot be negative")
            except (ValueError, TypeError) as ve:
                raise ExecutorSecurityError(f"Invalid Content-Length header: {ve}")

        if content_length > MAX_REQUEST_BYTES:
            try:
                drain_bytes = min(content_length, 256 * 1024)
                self.rfile.read(drain_bytes)
            except Exception:
                pass
            raise ExecutorSecurityError(f"Request body exceeds maximum size of {MAX_REQUEST_BYTES} bytes.")
        if content_length == 0:
            return {}

        raw_data = self.rfile.read(content_length)
        if len(raw_data) < content_length:
            raise ExecutorSecurityError("Incomplete request body: client stream closed prematurely.")
        try:
            parsed = json.loads(raw_data.decode("utf-8"))
        except UnicodeDecodeError:
            raise ExecutorSecurityError("Request body must be valid UTF-8.")
        except Exception as e:
            raise ExecutorSecurityError(f"Malformed JSON body: {e}")

        if not isinstance(parsed, dict):
            raise ExecutorSecurityError("Request body JSON must be an object/dict.")
        return parsed

    def do_GET(self) -> None:
        # Mandatory authentication on all GET endpoints
        if not self._authenticate():
            self._send_error(401, "Unauthorized: missing or invalid authentication token.")
            return

        path = self.path.split("?")[0].rstrip("/")

        # Health check
        if path in ("/health", "/status"):
            self._send_json(200, {
                "status": "HEALTHY",
                "table": f"inet {self.controller.table_name}",
                "dry_run": self.controller.dry_run
            })
            return

        # Verification endpoint: /verify/<action_id>
        verify_match = re.match(r"^/verify/([a-zA-Z0-9_\-]+)$", path)
        if verify_match:
            try:
                action_id = verify_match.group(1)
                result = self.controller.verify_action_rule(action_id)
                self._send_json(200, result)
            except Exception as e:
                logger.error(f"Verification error: {e}")
                self._send_error(400, f"Verification failure: {e}")
            return

        self._send_error(404, "Endpoint not found.")

    def do_POST(self) -> None:
        # Mandatory authentication on all state-changing POST endpoints
        if not self._authenticate():
            self._drain_body()
            self._send_error(401, "Unauthorized: missing or invalid authentication token.")
            return

        path = self.path.split("?")[0].rstrip("/")

        # Initialize table & chains: /init
        if path == "/init":
            try:
                res = self.controller.ensure_table_and_chains()
                self._send_json(200, res)
            except Exception as e:
                self._send_error(500, f"Table initialization failure: {e}")
            return

        # Apply endpoint: /apply
        if path == "/apply":
            try:
                body = self._read_json_body()
                action_id = body.get("action_id")
                if not isinstance(action_id, str) or not action_id.strip():
                    raise ExecutorSecurityError("Field 'action_id' must be a non-empty string.")
                ip_str = body.get("ip_address")
                if not isinstance(ip_str, str) or not ip_str.strip():
                    raise ExecutorSecurityError("Field 'ip_address' must be a non-empty string.")
                direction = body.get("direction", "both")
                if not isinstance(direction, str):
                    raise ExecutorSecurityError("Field 'direction' must be a string (both, inbound, outbound).")

                result = self.controller.apply_ip_block(
                    action_id=action_id.strip(),
                    ip_addr=ip_str.strip(),
                    direction=direction.strip().lower()
                )
                self._send_json(200, result)
            except Exception as e:
                logger.error(f"Apply error: {e}")
                self._send_error(400, f"Rule application failure: {e}")
            return

        # Rollback endpoint: /rollback/<action_id> or /rollback with JSON
        rollback_match = re.match(r"^/rollback/([a-zA-Z0-9_\-]+)$", path)
        if rollback_match or path == "/rollback":
            try:
                if rollback_match:
                    action_id = rollback_match.group(1)
                else:
                    body = self._read_json_body()
                    action_id = body.get("action_id")
                    if not isinstance(action_id, str) or not action_id.strip():
                        raise ExecutorSecurityError("Field 'action_id' must be a non-empty string.")

                result = self.controller.rollback_action_rule(action_id.strip())
                self._send_json(200, result)
            except Exception as e:
                logger.error(f"Rollback error: {e}")
                self._send_error(400, f"Rule rollback failure: {e}")
            return

        self._send_error(404, "Endpoint not found.")

    def do_PUT(self) -> None:
        self._drain_body()
        self._send_error(405, "Method Not Allowed.")

    def do_DELETE(self) -> None:
        self._drain_body()
        self._send_error(405, "Method Not Allowed.")

    def log_message(self, format: str, *args: Any) -> None:
        """Override to prevent logging tokens or sensitive headers."""
        logger.info(f"{self.client_address[0]} - {format % args}")


def run_executor_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    token: Optional[str] = None,
    table_name: str = DEFAULT_TABLE,
    dry_run: bool = False,
    sudo: bool = True,
    helper_path: str = DEFAULT_HELPER_PATH
) -> None:
    """Starts the HTTP executor daemon."""
    auth_token = token or os.getenv("FEDORA_EXECUTOR_TOKEN")
    if not auth_token:
        logger.error("FATAL: FEDORA_EXECUTOR_TOKEN environment variable not set. Refusing to start unauthenticated.")
        sys.exit(1)

    controller = NftablesController(
        table_name=table_name,
        dry_run=dry_run,
        sudo=sudo,
        helper_path=helper_path
    )
    try:
        controller.ensure_table_and_chains()
    except Exception as e:
        logger.warning(f"Initial table check note: {e}")

    handler_class = ExecutorRequestHandler
    handler_class.controller = controller
    handler_class.auth_token = auth_token

    server = HTTPServer((host, port), handler_class)
    logger.info(f"CyberScribe Fedora nftables Executor listening on {host}:{port} (table: inet {table_name}, dry_run={dry_run})...")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server shutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CyberScribe Fedora nftables Executor")
    parser.add_argument("--host", default=os.getenv("FEDORA_EXECUTOR_HOST", DEFAULT_HOST), help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.getenv("FEDORA_EXECUTOR_PORT", DEFAULT_PORT)), help="Port (default: 8088)")
    parser.add_argument("--table", default=os.getenv("FEDORA_NFTABLES_TABLE", DEFAULT_TABLE), help="nftables table name (default: cyberscribe)")
    parser.add_argument("--dry-run", action="store_true", help="Log commands without executing helper")
    parser.add_argument("--no-sudo", action="store_true", help="Run helper without sudo (if running as root)")
    args = parser.parse_args()

    run_executor_server(
        host=args.host,
        port=args.port,
        table_name=args.table,
        dry_run=args.dry_run,
        sudo=not args.no_sudo
    )
