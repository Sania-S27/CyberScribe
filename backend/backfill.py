# backend/backfill.py
from app.core.database import SessionLocal
from app.models import ThreatReport
from app.agents.analyst import analyze_threat_with_llm
from app.agents.reporter import generate_stix_report
from app.schemas.analyst import ThreatAnalysisResult
import json

db = SessionLocal()
broken_reports = db.query(ThreatReport).filter((ThreatReport.stix_bundle == "null") | (ThreatReport.stix_bundle == None)).all()

print(f"🔄 Found {len(broken_reports)} reports missing STIX bundles. Fixing...")

for report in broken_reports:
    try:
        # Re-run the analysis and STIX generation using our stabilized pipeline
        analysis_dict = analyze_threat_with_llm(report.summary)
        analysis_obj = ThreatAnalysisResult(**analysis_dict)
        stix_bundle = generate_stix_report(analysis_obj)
        
        # Update the row
        report.stix_bundle = json.dumps(stix_bundle.model_dump())
        if analysis_dict.get("cve_id"):
            report.cve_id = analysis_dict.get("cve_id")
        report.severity = analysis_dict.get("severity", report.severity)
        
        db.commit()
        print(f"✅ Fixed STidX for: {report.title}")
    except Exception as e:
        print(f"❌ Failed to fix report {report.id}: {e}")

db.close()
print("🎉 Backfill complete! Refresh your UI.")