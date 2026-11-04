# backend/scripts/download_mitre_dataset.py
import os
import sys
import json
import time
import requests
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "app" / "data" / "mitre_attack"
DATA_DIR.mkdir(parents=True, exist_ok=True)

OFFICIAL_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OFFICIAL_VERSION = "v16.1 (Enterprise ATT&CK STIX 2.1)"
SOURCE_URL = "https://github.com/mitre-attack/attack-stix-data"
RETRIEVAL_DATE = "2026-10-10"

def fetch_and_index_mitre_attack():
    print(f"Fetching official MITRE ATT&CK STIX dataset from {OFFICIAL_URL}...")
    headers = {"User-Agent": "CyberScribe-MITRE-KB/1.0"}
    
    stix_file_path = DATA_DIR / "enterprise-attack.json"
    index_file_path = DATA_DIR / "attack_techniques.json"
    metadata_file_path = DATA_DIR / "metadata.json"
    
    # Try downloading official dataset with retry/timeout
    stix_data = None
    if stix_file_path.exists() and stix_file_path.stat().st_size > 1000000:
        print(f"Loading cached STIX dataset from {stix_file_path}...")
        with open(stix_file_path, "r", encoding="utf-8") as f:
            stix_data = json.load(f)
    else:
        for attempt in range(1, 4):
            try:
                print(f"Download attempt {attempt}/3...")
                res = requests.get(OFFICIAL_URL, headers=headers, timeout=60)
                if res.status_code == 200:
                    stix_data = res.json()
                    with open(stix_file_path, "w", encoding="utf-8") as f:
                        json.dump(stix_data, f)
                    print(f"Saved raw STIX dataset to {stix_file_path} ({len(res.content)} bytes)")
                    break
                else:
                    print(f"Attempt {attempt} returned status {res.status_code}")
            except Exception as e:
                print(f"Attempt {attempt} failed: {e}")
                time.sleep(2)
                
    if not stix_data or "objects" not in stix_data:
        raise RuntimeError("Could not obtain MITRE ATT&CK STIX 2.1 dataset.")

    # Parse and index techniques
    techniques_index = {}
    active_count = 0
    revoked_count = 0
    deprecated_count = 0
    subtechnique_count = 0
    
    # Collect tactics metadata
    tactics_map = {}
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname")
            tactic_name = obj.get("name")
            if shortname:
                tactics_map[shortname] = tactic_name

    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
            
        ext_refs = obj.get("external_references", [])
        tech_id = None
        url = None
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                url = ref.get("url")
                break
                
        if not tech_id:
            continue
            
        is_revoked = bool(obj.get("revoked", False))
        is_deprecated = bool(obj.get("x_mitre_deprecated", False))
        is_sub = bool(obj.get("x_mitre_is_subtechnique", False))
        
        if is_revoked:
            revoked_count += 1
        if is_deprecated:
            deprecated_count += 1
        if is_sub:
            subtechnique_count += 1
            
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name")
                tactics.append({
                    "shortname": phase_name,
                    "name": tactics_map.get(phase_name, phase_name.replace("-", " ").title())
                })
                
        techniques_index[tech_id] = {
            "technique_id": tech_id,
            "name": obj.get("name", "Unknown Technique"),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "primary_tactic": tactics[0]["shortname"] if tactics else "initial-access",
            "is_subtechnique": is_sub,
            "is_revoked": is_revoked,
            "is_deprecated": is_deprecated,
            "platforms": obj.get("x_mitre_platforms", []),
            "url": url or f"https://attack.mitre.org/techniques/{tech_id}",
            "stix_id": obj.get("id")
        }
        if not is_revoked and not is_deprecated:
            active_count += 1

    metadata = {
        "dataset_name": "MITRE ATT&CK Enterprise",
        "dataset_version": OFFICIAL_VERSION,
        "source_url": SOURCE_URL,
        "raw_data_url": OFFICIAL_URL,
        "retrieval_date": RETRIEVAL_DATE,
        "total_techniques_and_subtechniques": len(techniques_index),
        "active_techniques": active_count,
        "revoked_techniques": revoked_count,
        "deprecated_techniques": deprecated_count,
        "subtechniques": subtechnique_count
    }

    with open(index_file_path, "w", encoding="utf-8") as f:
        json.dump(techniques_index, f, indent=2)
        
    with open(metadata_file_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
        
    print(f"\nIndexed {len(techniques_index)} total MITRE ATT&CK techniques:")
    print(f"  - Active: {active_count}")
    print(f"  - Subtechniques: {subtechnique_count}")
    print(f"  - Revoked: {revoked_count}")
    print(f"  - Deprecated: {deprecated_count}")
    print(f"Saved indexed lookup to {index_file_path}")
    print(f"Saved KB metadata to {metadata_file_path}")

if __name__ == "__main__":
    fetch_and_index_mitre_attack()
