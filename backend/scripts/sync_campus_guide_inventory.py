# backend/scripts/sync_campus_guide_inventory.py
import sys
import os
import uuid
from typing import Dict, List, Tuple

# Ensure stdout uses utf-8 encoding on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.database import SessionLocal
from app.models import Tenant, AssetComponent, ThreatMatch, ThreatReport
from app.services.version_matcher import evaluate_version_applicability, normalize_package_name

VERIFIED_BACKEND_VERSIONS: Dict[str, str] = {
    "fastapi": "0.120.1",
    "sqlalchemy": "2.0.44",
    "uvicorn": "0.38.0",
    "pymysql": "1.1.2",
    "passlib": "1.7.4",
    "python-jose": "3.5.0",
    "python-dotenv": "1.2.1",
    "httpx": "0.28.1",
    "thefuzz": "0.22.1",
    "python-Levenshtein": "0.27.3",
    "cryptography": "46.0.3",
    "bcrypt": "5.0.0",
    "pydantic": "2.12.3",
    "starlette": "0.49.1",
    "apscheduler": "3.11.1",
}

VERIFIED_FRONTEND_VERSIONS: Dict[str, str] = {
    "react": "19.2.0",
    "react-dom": "19.2.0",
    "react-router-dom": "7.9.4",
    "axios": "1.13.1",
    "mapbox-gl": "3.16.0",
    "react-map-gl": "7.1.9",
    "react-scripts": "5.0.1",
}

TECH_STACK_SUMMARY = (
    "FastAPI 0.120.1, SQLAlchemy 2.0.44, PyMySQL 1.1.2, React 19.2.0, "
    "Mapbox-GL 3.16.0, Uvicorn 0.38.0, APScheduler 3.11.1, Passlib 1.7.4, Python-JOSE 3.5.0"
)


def sync_inventory_and_matches():
    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.company_name == "Campus Guide").first()
        if not tenant:
            print("[!] Tenant 'Campus Guide' not found.")
            return

        print(f"[*] Found Tenant: {tenant.company_name} (ID: {tenant.id})")

        # 1. Update Tech Stack
        tenant.tech_stack = TECH_STACK_SUMMARY
        print(f"[*] Updated tech_stack to: {tenant.tech_stack}")

        # 2. Existing components map
        existing_assets = db.query(AssetComponent).filter(AssetComponent.tenant_id == tenant.id).all()
        existing_by_name = {normalize_package_name(a.software_name): a for a in existing_assets}

        all_verified = {**VERIFIED_BACKEND_VERSIONS, **VERIFIED_FRONTEND_VERSIONS}
        
        updated_count = 0
        added_count = 0

        # Update existing or add new
        for pkg_name, ver in all_verified.items():
            norm_name = normalize_package_name(pkg_name)
            if norm_name in existing_by_name:
                asset = existing_by_name[norm_name]
                if asset.software_version != ver:
                    print(f"  - Updating {asset.software_name}: '{asset.software_version}' -> '{ver}'")
                    asset.software_version = ver
                    updated_count += 1
            else:
                print(f"  + Registering missing component: {pkg_name} == {ver}")
                new_asset = AssetComponent(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant.id,
                    software_name=pkg_name,
                    software_version=ver,
                    environment="production"
                )
                db.add(new_asset)
                added_count += 1

        db.commit()
        print(f"[SUCCESS] Inventory sync complete: {updated_count} updated, {added_count} registered.")

        # 3. Re-evaluate existing threat matches
        matches = db.query(ThreatMatch).filter(ThreatMatch.tenant_id == tenant.id).all()
        print(f"\n[*] Re-evaluating {len(matches)} historical threat matches for {tenant.company_name}...")

        evaluation_results = []
        for idx, match in enumerate(matches, 1):
            report = db.query(ThreatReport).filter(ThreatReport.id == match.threat_report_id).first()
            if not report:
                continue

            corpus = f"{report.title or ''} {report.summary or ''}".strip()
            
            # Find which component in the verified inventory was matched
            evaluated_status = "NOT_AFFECTED"
            best_reason = f"[NOT AFFECTED] No active component in verified inventory affected by {report.cve_id or report.title}."
            best_conf = 0.0

            for pkg_name, ver in all_verified.items():
                classification, conf, reason = evaluate_version_applicability(
                    installed_version=ver,
                    threat_text=corpus,
                    pkg_name=pkg_name
                )
                if classification == "AFFECTED":
                    evaluated_status = "AFFECTED"
                    best_reason = reason
                    best_conf = conf
                    break
                elif classification == "NEEDS_REVIEW" and evaluated_status != "AFFECTED":
                    evaluated_status = "NEEDS_REVIEW"
                    best_reason = reason
                    best_conf = conf
                elif classification == "NOT_AFFECTED" and conf > 0 and evaluated_status == "NOT_AFFECTED":
                    best_reason = reason
                    best_conf = conf

            # Map tri-state classification to database ThreatMatch status
            old_status = match.status
            if old_status in ["RESOLVED", "patched", "mitigated"]:
                new_status = "RESOLVED"
            else:
                new_status = "OPEN"

            match.status = new_status
            match.ai_matching_reason = best_reason
            if best_conf > 0:
                match.ai_confidence_score = best_conf

            evaluation_results.append({
                "index": idx,
                "match_id": match.id,
                "cve_id": report.cve_id or "N/A",
                "title": report.title,
                "old_status": old_status,
                "new_status": new_status,
                "classification": evaluated_status,
                "reason": best_reason
            })

        db.commit()

        print("\n" + "=" * 90)
        print(f"{'#':<3} | {'CVE ID':<15} | {'Class':<13} | {'Old Status':<10} -> {'New Status':<10} | Reason")
        print("-" * 90)
        for r in evaluation_results:
            print(f"{r['index']:<3} | {r['cve_id']:<15} | {r['classification']:<13} | {r['old_status']:<10} -> {r['new_status']:<10} | {r['reason'][:60]}")
        print("=" * 90)
        print(f"[SUCCESS] All {len(matches)} historical threat matches preserved and re-evaluated.")

    except Exception as e:
        db.rollback()
        print(f"[ERROR] Error during sync: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()


if __name__ == "__main__":
    sync_inventory_and_matches()
