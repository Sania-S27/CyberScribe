"""
CyberScribe Modular Patch Management Adapter
---------------------------------------------
Implements safe, audited software vulnerability patch management:
- Package manager detection (dnf, apt, yum, pip)
- Input sanitization & eligibility checks (allowlisted operations, no arbitrary commands)
- Proposal lifecycle: PROPOSED -> APPROVED/REJECTED -> SIMULATED/APPLIED -> VERIFIED
- Default mode: SIMULATED (dry-run)
- Live execution: Requires explicit approval, runs argument arrays (no shell=True)
- Installed-version verification read-back
- Non-repudiation audit logging in `_patch_audit_logs`
- Strict tenant isolation
"""

import os
import sys
import re
import uuid
import shutil
import logging
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models import PatchProposal, PatchAuditLog, ThreatMatch, AssetComponent

logger = logging.getLogger("PatchManagementAdapter")

# Strict Allowlist: package names must be alphanumeric with standard separators
PACKAGE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{2,128}$")
VERSION_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.\:\+]{1,64}$")

DEFAULT_CAMPUS_GUIDE_PYTHON = r"E:\Campus Guide Project\backend\venv\Scripts\python.exe"


def _get_python_bin() -> str:
    """
    Returns the trusted Python interpreter path for target package operations.
    Priority:
    1. Explicit CAMPUS_GUIDE_PYTHON_PATH or TARGET_PYTHON_PATH environment variable if configured.
    2. Verified Campus Guide target virtualenv at 'E:\\Campus Guide Project\\backend\\venv\\Scripts\\python.exe'.
    3. CyberScribe's own virtualenv (sys.executable) as local fallback.
    """
    for env_var in ("CAMPUS_GUIDE_PYTHON_PATH", "TARGET_PYTHON_PATH"):
        explicit = os.getenv(env_var)
        if explicit:
            return explicit

    if os.path.exists(DEFAULT_CAMPUS_GUIDE_PYTHON):
        return DEFAULT_CAMPUS_GUIDE_PYTHON

    return sys.executable


SUPPORTED_PACKAGE_MANAGERS = {
    "dnf": {
        "update_cmd": lambda pkg, ver: ["dnf", "update", "-y", f"{pkg}-{ver}" if ver else pkg],
        "verify_cmd": lambda pkg: ["rpm", "-q", pkg],
        "check_cmd": lambda pkg: ["dnf", "check-update", pkg]
    },
    "apt": {
        "update_cmd": lambda pkg, ver: ["apt-get", "install", "--only-upgrade", "-y", f"{pkg}={ver}" if ver else pkg],
        "verify_cmd": lambda pkg: ["dpkg-query", "-W", "-f=${Status} ${Version}", pkg],
        "check_cmd": lambda pkg: ["apt-get", "--just-print", "upgrade", pkg]
    },
    "yum": {
        "update_cmd": lambda pkg, ver: ["yum", "update", "-y", f"{pkg}-{ver}" if ver else pkg],
        "verify_cmd": lambda pkg: ["rpm", "-q", pkg],
        "check_cmd": lambda pkg: ["yum", "check-update", pkg]
    },
    "pip": {
        "update_cmd": lambda pkg, ver: [_get_python_bin(), "-m", "pip", "install", "--upgrade", f"{pkg}=={ver}" if ver else pkg],
        "verify_cmd": lambda pkg: [_get_python_bin(), "-m", "pip", "show", pkg],
        "check_cmd": lambda pkg: [_get_python_bin(), "-m", "pip", "list", "--outdated"]
    }
}


def parse_installed_version(package_manager: str, verify_stdout: str, package_name: str) -> Optional[str]:
    """
    Independently parses the installed version string from verify command stdout.
    - pip (pip show <pkg>): extracts from 'Version: <version>'
    - apt (dpkg-query): extracts from 'install ok installed <version>'
    - dnf/yum (rpm -q <pkg>): extracts version from '<pkg>-<ver>-<rel>.<arch>'
    """
    if not verify_stdout:
        return None

    pm = (package_manager or "").lower()

    if pm == "pip":
        m = re.search(r"(?im)^Version:\s*([a-zA-Z0-9_\-\.\:\+]+)", verify_stdout)
        if m:
            return m.group(1).strip()

    elif pm == "apt":
        m = re.search(r"(?im)installed\s+([a-zA-Z0-9_\-\.\:\+]+)", verify_stdout)
        if m:
            return m.group(1).strip()

    elif pm in ("dnf", "yum"):
        clean_out = verify_stdout.strip().splitlines()[0] if verify_stdout.strip() else ""
        escaped_pkg = re.escape(package_name)
        m = re.search(rf"(?:{escaped_pkg}-)?([0-9][a-zA-Z0-9_\-\.\:\+]*)", clean_out)
        if m:
            ver_candidate = m.group(1)
            return ver_candidate.split("-")[0]

    return None


def verify_version_match(installed_version: str, target_version: str) -> bool:
    """Checks if installed version matches target version constraint or string."""
    if not installed_version or not target_version:
        return False
    try:
        from packaging.version import parse as parse_v
        return parse_v(installed_version) == parse_v(target_version)
    except Exception:
        return installed_version.strip().lower() == target_version.strip().lower()


class PatchSecurityError(Exception):
    """Raised when patch arguments violate security constraints."""
    pass


class PatchStateError(Exception):
    """Raised on invalid lifecycle state transitions."""
    pass


class PatchManagementAdapter:
    """Safe, modular software patch management adapter."""

    @staticmethod
    def detect_package_manager() -> str:
        """Detects host package manager or defaults to 'dnf' for Fedora/RHEL."""
        for pm in ("dnf", "apt-get", "yum", "pip"):
            if shutil.which(pm):
                return "apt" if pm == "apt-get" else pm
        return "dnf"

    @classmethod
    def validate_package_spec(cls, package_name: str, target_version: Optional[str] = None) -> Tuple[str, Optional[str]]:
        """Strictly validates package name and version against injection metacharacters."""
        if not package_name or not isinstance(package_name, str):
            raise PatchSecurityError("Package name must be a non-empty string.")
        
        clean_pkg = package_name.strip()
        if not PACKAGE_NAME_REGEX.match(clean_pkg):
            raise PatchSecurityError(f"Invalid package name '{clean_pkg}'. Must match {PACKAGE_NAME_REGEX.pattern}")

        clean_ver = None
        if target_version:
            clean_ver = str(target_version).strip()
            if not VERSION_REGEX.match(clean_ver):
                raise PatchSecurityError(f"Invalid version format '{clean_ver}'. Must match {VERSION_REGEX.pattern}")

        return clean_pkg, clean_ver

    @classmethod
    def create_proposal(
        cls,
        db: Session,
        tenant_id: str,
        package_name: str,
        current_version: Optional[str] = None,
        target_version: Optional[str] = None,
        threat_match_id: Optional[str] = None,
        asset_component_id: Optional[str] = None,
        priority: str = "HIGH",
        package_manager: Optional[str] = None,
        actor: str = "AUTONOMOUS_PATCH_ENGINE",
        is_authoritative: bool = True,
        live_execution_blocked: bool = False,
        blocking_reason: Optional[str] = None
    ) -> PatchProposal:
        """Creates a verified remediation patch proposal in PROPOSED state."""
        clean_pkg, clean_ver = cls.validate_package_spec(package_name, target_version)
        if package_manager and package_manager not in SUPPORTED_PACKAGE_MANAGERS:
            raise PatchSecurityError(
                f"Unsupported package manager: '{package_manager}'. "
                f"Supported: {sorted(list(SUPPORTED_PACKAGE_MANAGERS.keys()))}"
            )
        pm = package_manager or cls.detect_package_manager()
        if pm not in SUPPORTED_PACKAGE_MANAGERS:
            raise PatchSecurityError(
                f"Detected package manager '{pm}' is not in supported list: "
                f"{sorted(list(SUPPORTED_PACKAGE_MANAGERS.keys()))}"
            )

        # Idempotency check: Reuse existing active proposal for same threat match or package
        if threat_match_id:
            existing_prop = db.query(PatchProposal).filter(
                PatchProposal.tenant_id == tenant_id,
                PatchProposal.threat_match_id == threat_match_id,
                PatchProposal.package_name == clean_pkg,
                PatchProposal.target_version == clean_ver
            ).first()
        else:
            existing_prop = db.query(PatchProposal).filter(
                PatchProposal.tenant_id == tenant_id,
                PatchProposal.package_name == clean_pkg,
                PatchProposal.target_version == clean_ver,
                PatchProposal.status.in_(["PROPOSED", "APPROVED", "SIMULATED", "APPLIED", "VERIFIED"])
            ).first()
        if existing_prop:
            logger.info(f"Existing proposal '{existing_prop.proposal_id}' already active for {clean_pkg}=={clean_ver}. Reusing.")
            return existing_prop

        pm_spec = SUPPORTED_PACKAGE_MANAGERS[pm]
        cmd = pm_spec["update_cmd"](clean_pkg, clean_ver)
        verify_cmd = pm_spec["verify_cmd"](clean_pkg)

        proposal_id = f"patch-{uuid.uuid4().hex[:12]}"
        proposal = PatchProposal(
            proposal_id=proposal_id,
            tenant_id=tenant_id,
            threat_match_id=threat_match_id,
            asset_component_id=asset_component_id,
            package_name=clean_pkg,
            current_version=current_version,
            target_version=clean_ver,
            package_manager=pm,
            priority=priority.upper(),
            status="PROPOSED",
            is_simulated=True,
            command_spec={"command": cmd, "package_manager": pm},
            verification_spec={
                "verify_command": verify_cmd,
                "expected_package": clean_pkg,
                "is_authoritative": is_authoritative,
                "live_execution_blocked": live_execution_blocked,
                "blocking_reason": blocking_reason
            }
        )
        db.add(proposal)
        db.commit()
        db.refresh(proposal)

        # Audit Record
        cls._record_audit(
            db=db,
            proposal_id=proposal.id,
            tenant_id=tenant_id,
            event_type="PROPOSAL_CREATED",
            actor=actor,
            previous_status=None,
            new_status="PROPOSED",
            details={
                "proposal_id": proposal.proposal_id,
                "package": clean_pkg,
                "current_version": current_version,
                "target_version": clean_ver,
                "command": cmd
            }
        )
        return proposal

    @classmethod
    def approve_proposal(
        cls,
        db: Session,
        proposal_id: str,
        approver: str,
        tenant_id: Optional[str] = None
    ) -> PatchProposal:
        """Authorizes a patch proposal for execution. Transitions PROPOSED -> APPROVED."""
        query = db.query(PatchProposal).filter(
            (PatchProposal.proposal_id == proposal_id) | (PatchProposal.id == proposal_id)
        )
        if tenant_id:
            query = query.filter(PatchProposal.tenant_id == tenant_id)
        
        proposal = query.first()
        if not proposal:
            raise PatchStateError(f"Patch proposal '{proposal_id}' not found.")

        if proposal.status == "APPROVED":
            return proposal

        if proposal.status != "PROPOSED":
            raise PatchStateError(f"Cannot approve proposal in status '{proposal.status}'. Required: 'PROPOSED'.")

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        prev_status = proposal.status
        proposal.status = "APPROVED"
        proposal.approved_by = approver
        proposal.approved_at = now
        db.commit()
        db.refresh(proposal)

        cls._record_audit(
            db=db,
            proposal_id=proposal.id,
            tenant_id=proposal.tenant_id,
            event_type="PROPOSAL_APPROVED",
            actor=approver,
            previous_status=prev_status,
            new_status="APPROVED",
            details={"approved_by": approver, "timestamp": now.isoformat()}
        )
        return proposal

    @classmethod
    def reject_proposal(
        cls,
        db: Session,
        proposal_id: str,
        reason: str,
        actor: str,
        tenant_id: Optional[str] = None
    ) -> PatchProposal:
        """Rejects a patch proposal. Transitions PROPOSED/APPROVED -> REJECTED."""
        query = db.query(PatchProposal).filter(
            (PatchProposal.proposal_id == proposal_id) | (PatchProposal.id == proposal_id)
        )
        if tenant_id:
            query = query.filter(PatchProposal.tenant_id == tenant_id)
        
        proposal = query.first()
        if not proposal:
            raise PatchStateError(f"Patch proposal '{proposal_id}' not found.")

        if proposal.status not in ("PROPOSED", "APPROVED"):
            raise PatchStateError(f"Cannot reject proposal in terminal status '{proposal.status}'.")

        prev_status = proposal.status
        proposal.status = "REJECTED"
        proposal.error_message = f"Rejected by {actor}: {reason}"
        db.commit()
        db.refresh(proposal)

        cls._record_audit(
            db=db,
            proposal_id=proposal.id,
            tenant_id=proposal.tenant_id,
            event_type="PROPOSAL_REJECTED",
            actor=actor,
            previous_status=prev_status,
            new_status="REJECTED",
            details={"reason": reason, "rejected_by": actor}
        )
        return proposal

    @classmethod
    def execute_patch(
        cls,
        db: Session,
        proposal_id: str,
        actor: str = "AUTONOMOUS_PATCH_ENGINE",
        mode: str = "simulated",
        tenant_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes a patch proposal.
        In simulated mode (default): Generates verified dry-run output and updates audit history.
        In live mode: Executes allowlisted command array, captures output, and verifies version read-back.
        """
        query = db.query(PatchProposal).filter(
            (PatchProposal.proposal_id == proposal_id) | (PatchProposal.id == proposal_id)
        )
        if tenant_id:
            query = query.filter(PatchProposal.tenant_id == tenant_id)
        
        proposal = query.first()
        if not proposal:
            raise PatchStateError(f"Patch proposal '{proposal_id}' not found.")

        # Idempotency / Duplicate request check
        if proposal.status in ("VERIFIED", "SIMULATED", "APPLIED"):
            return {
                "status": proposal.status,
                "proposal_id": proposal.proposal_id,
                "package_name": proposal.package_name,
                "is_simulated": proposal.is_simulated,
                "output": proposal.execution_output,
                "verification": proposal.verification_output,
                "message": f"Proposal '{proposal.proposal_id}' was already executed ({proposal.status}). Duplicate request safely handled."
            }

        if proposal.status != "APPROVED":
            raise PatchStateError(f"Cannot execute proposal in status '{proposal.status}'. Must be 'APPROVED'.")

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        cmd = proposal.command_spec.get("command") if proposal.command_spec else None
        verify_cmd = proposal.verification_spec.get("verify_command") if proposal.verification_spec else None

        if not cmd or not isinstance(cmd, list):
            raise PatchSecurityError("Invalid command specification in proposal.")

        # --- SIMULATED EXECUTION (DEFAULT) ---
        if mode.lower() in ("simulated", "dry_run", "simulation"):
            sim_output = (
                f"[SIMULATION DRY-RUN]\n"
                f"Package Manager: {proposal.package_manager}\n"
                f"Target Package:  {proposal.package_name}\n"
                f"Planned Command: {' '.join(cmd)}\n"
                f"Simulated Result: SUCCESS - Version {proposal.target_version or 'latest'} staged for deployment.\n"
            )
            sim_verify = (
                f"[SIMULATION VERIFICATION]\n"
                f"Verification Command: {' '.join(verify_cmd) if verify_cmd else 'N/A'}\n"
                f"Simulated Readback: Package '{proposal.package_name}' satisfies target version constraint.\n"
            )

            prev_status = proposal.status
            proposal.status = "SIMULATED"
            proposal.is_simulated = True
            proposal.execution_output = sim_output
            proposal.verification_output = sim_verify
            proposal.applied_at = now
            proposal.verified_at = now
            db.commit()
            db.refresh(proposal)

            cls._record_audit(
                db=db,
                proposal_id=proposal.id,
                tenant_id=proposal.tenant_id,
                event_type="PATCH_SIMULATED",
                actor=actor,
                previous_status=prev_status,
                new_status="SIMULATED",
                details={
                    "mode": "simulated",
                    "command": cmd,
                    "simulated_output": sim_output
                }
            )

            return {
                "status": "SIMULATED",
                "proposal_id": proposal.proposal_id,
                "package_name": proposal.package_name,
                "is_simulated": True,
                "output": sim_output,
                "verification": sim_verify
            }

        # --- LIVE EXECUTION (CONTROLLED TARGET ONLY) ---
        if mode.lower() in ("live", "live_windows", "live_fedora"):
            # Block unverified / inferred candidate proposals from live execution without authoritative vendor proof
            v_spec = proposal.verification_spec or {}
            if v_spec.get("live_execution_blocked"):
                reason = v_spec.get("blocking_reason", "Remediation proposal blocked: candidate version lacks authoritative vendor verification.")
                prev_status = proposal.status
                proposal.status = "FAILED"
                proposal.error_message = reason
                db.commit()
                cls._record_audit(
                    db=db,
                    proposal_id=proposal.id,
                    tenant_id=proposal.tenant_id,
                    event_type="PATCH_FAILED",
                    actor=actor,
                    previous_status=prev_status,
                    new_status="FAILED",
                    details={"error": reason, "phase": "authoritative_verification_guard"}
                )
                return {"status": "FAILED", "error": reason}

            # Target isolation guard: prevent accidental live modification of CyberScribe's own virtualenv
            if proposal.package_manager == "pip":
                target_py = os.path.abspath(_get_python_bin())
                cyberscribe_py = os.path.abspath(sys.executable)

                # Check if target interpreter exists on disk
                if not os.path.exists(target_py):
                    prev_status = proposal.status
                    proposal.status = "FAILED"
                    proposal.error_message = f"Target interpreter does not exist at '{target_py}'. Execution halted."
                    db.commit()
                    cls._record_audit(
                        db=db,
                        proposal_id=proposal.id,
                        tenant_id=proposal.tenant_id,
                        event_type="PATCH_FAILED",
                        actor=actor,
                        previous_status=prev_status,
                        new_status="FAILED",
                        details={"error": proposal.error_message, "phase": "target_interpreter_missing"}
                    )
                    return {"status": "FAILED", "error": proposal.error_message}

                allow_self = os.getenv("ALLOW_SELF_PATCHING", "false").strip().lower() == "true"
                if target_py == cyberscribe_py and not allow_self:
                    prev_status = proposal.status
                    proposal.status = "FAILED"
                    proposal.error_message = (
                        f"Target interpreter safety check failed: resolved to CyberScribe's own virtualenv "
                        f"({cyberscribe_py}) rather than target host virtualenv. Set CAMPUS_GUIDE_PYTHON_PATH "
                        f"or ALLOW_SELF_PATCHING=true."
                    )
                    db.commit()
                    cls._record_audit(
                        db=db,
                        proposal_id=proposal.id,
                        tenant_id=proposal.tenant_id,
                        event_type="PATCH_FAILED",
                        actor=actor,
                        previous_status=prev_status,
                        new_status="FAILED",
                        details={"error": proposal.error_message, "phase": "interpreter_isolation_guard"}
                    )
                    return {"status": "FAILED", "error": proposal.error_message}
            try:
                # Execute allowlisted command with arguments array (never shell=True)
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=45,
                    shell=False
                )
                output = f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
                if proc.returncode != 0:
                    prev_status = proposal.status
                    proposal.status = "FAILED"
                    proposal.error_message = f"Command failed with exit code {proc.returncode}: {proc.stderr[:500]}"
                    proposal.execution_output = output
                    db.commit()

                    cls._record_audit(
                        db=db,
                        proposal_id=proposal.id,
                        tenant_id=proposal.tenant_id,
                        event_type="PATCH_FAILED",
                        actor=actor,
                        previous_status=prev_status,
                        new_status="FAILED",
                        details={"exit_code": proc.returncode, "error": proc.stderr[:500]}
                    )
                    return {"status": "FAILED", "error": proposal.error_message, "output": output}

                # Independent Verification Read-back
                ver_output = "No verify command configured"
                installed_version = None
                if verify_cmd and isinstance(verify_cmd, list):
                    ver_proc = subprocess.run(
                        verify_cmd,
                        capture_output=True,
                        text=True,
                        timeout=15,
                        shell=False
                    )
                    ver_output = f"STDOUT:\n{ver_proc.stdout}\nSTDERR:\n{ver_proc.stderr}"
                    if ver_proc.returncode != 0:
                        prev_status = proposal.status
                        proposal.status = "FAILED"
                        proposal.error_message = f"Verification check failed with exit code {ver_proc.returncode}: {ver_proc.stderr[:500]}"
                        proposal.execution_output = output
                        proposal.verification_output = ver_output
                        db.commit()
                        cls._record_audit(
                            db=db,
                            proposal_id=proposal.id,
                            tenant_id=proposal.tenant_id,
                            event_type="PATCH_FAILED",
                            actor=actor,
                            previous_status=prev_status,
                            new_status="FAILED",
                            details={"exit_code": ver_proc.returncode, "error": ver_proc.stderr[:500], "phase": "verification_exit_code"}
                        )
                        return {"status": "FAILED", "error": proposal.error_message, "output": output, "verification": ver_output}

                    # Independently parse installed version from verification output
                    installed_version = parse_installed_version(proposal.package_manager, ver_proc.stdout, proposal.package_name)

                    if proposal.target_version:
                        if not installed_version:
                            prev_status = proposal.status
                            proposal.status = "FAILED"
                            proposal.error_message = "Inconclusive verification: could not extract installed version from output."
                            proposal.execution_output = output
                            proposal.verification_output = ver_output
                            db.commit()
                            cls._record_audit(
                                db=db,
                                proposal_id=proposal.id,
                                tenant_id=proposal.tenant_id,
                                event_type="PATCH_FAILED",
                                actor=actor,
                                previous_status=prev_status,
                                new_status="FAILED",
                                details={"error": proposal.error_message, "phase": "verification_inconclusive"}
                            )
                            return {"status": "FAILED", "error": proposal.error_message, "output": output, "verification": ver_output}

                        if not verify_version_match(installed_version, proposal.target_version):
                            prev_status = proposal.status
                            proposal.status = "FAILED"
                            proposal.error_message = (
                                f"Version verification mismatch: target version was '{proposal.target_version}', "
                                f"but installed version is '{installed_version}'."
                            )
                            proposal.execution_output = output
                            proposal.verification_output = ver_output
                            db.commit()
                            cls._record_audit(
                                db=db,
                                proposal_id=proposal.id,
                                tenant_id=proposal.tenant_id,
                                event_type="PATCH_FAILED",
                                actor=actor,
                                previous_status=prev_status,
                                new_status="FAILED",
                                details={
                                    "error": proposal.error_message,
                                    "target_version": proposal.target_version,
                                    "installed_version": installed_version,
                                    "phase": "verification_mismatch"
                                }
                            )
                            return {
                                "status": "FAILED",
                                "error": proposal.error_message,
                                "target_version": proposal.target_version,
                                "installed_version": installed_version,
                                "output": output,
                                "verification": ver_output
                            }

                prev_status = proposal.status
                proposal.status = "VERIFIED"
                proposal.is_simulated = False
                proposal.execution_output = output
                proposal.verification_output = ver_output
                proposal.applied_at = now
                proposal.verified_at = now

                # If linked to a ThreatMatch, transition ThreatMatch to RESOLVED
                if proposal.threat_match_id:
                    match = db.query(ThreatMatch).filter(ThreatMatch.id == proposal.threat_match_id).first()
                    if match:
                        match.status = "RESOLVED"

                db.commit()
                db.refresh(proposal)

                cls._record_audit(
                    db=db,
                    proposal_id=proposal.id,
                    tenant_id=proposal.tenant_id,
                    event_type="PATCH_VERIFIED",
                    actor=actor,
                    previous_status=prev_status,
                    new_status="VERIFIED",
                    details={"output": output[:500], "verification": ver_output[:500]}
                )

                return {
                    "status": "VERIFIED",
                    "proposal_id": proposal.proposal_id,
                    "package_name": proposal.package_name,
                    "is_simulated": False,
                    "output": output,
                    "verification": ver_output
                }

            except subprocess.TimeoutExpired as te:
                prev_status = proposal.status
                proposal.status = "FAILED"
                proposal.error_message = f"Execution timed out after {te.timeout}s"
                db.commit()
                return {"status": "FAILED", "error": proposal.error_message}
            except Exception as e:
                prev_status = proposal.status
                proposal.status = "FAILED"
                proposal.error_message = str(e)
                db.commit()
                return {"status": "FAILED", "error": str(e)}

        raise PatchSecurityError(f"Unsupported execution mode '{mode}'. Choose 'simulated' or 'live'.")

    @classmethod
    def _record_audit(
        cls,
        db: Session,
        proposal_id: str,
        tenant_id: str,
        event_type: str,
        actor: str,
        previous_status: Optional[str],
        new_status: str,
        details: Optional[Dict[str, Any]] = None
    ) -> PatchAuditLog:
        """Creates an immutable audit log record for patch lifecycle events."""
        audit_entry = PatchAuditLog(
            proposal_id=proposal_id,
            tenant_id=tenant_id,
            event_type=event_type,
            actor=actor,
            previous_status=previous_status,
            new_status=new_status,
            details=details or {}
        )
        db.add(audit_entry)
        db.commit()
        return audit_entry
