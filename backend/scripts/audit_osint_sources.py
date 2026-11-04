# backend/scripts/audit_osint_sources.py
import sys
import io
import time
import requests
import feedparser
from datetime import datetime
from pathlib import Path

# Ensure UTF-8 output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.core.database import SessionLocal, engine
from app import models
from app.services.osint_collector import OSINT_FEEDS, ACTIONABLE_KEYWORDS, clean_package_name
from app.core.chroma import threat_collection
from app.services.vector_store import query_similar_threats, format_retrieved_threats_for_prompt

def audit_nvd_source():
    print("\n" + "="*50)
    print("AUDITING SOURCE: NVD REST 2.0 API (Targeted)")
    print("="*50)
    
    db = SessionLocal()
    results = {
        "source": "NVD REST 2.0 API",
        "type": "REST API",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "http_status": None,
        "connection_success": False,
        "content_returned": False,
        "entry_count": 0,
        "pub_date_extracted": False,
        "pub_date_sample": None,
        "actionability_filter": "N/A (Targeted CVEs treated by severity)",
        "duplicate_detection": False,
        "error": None
    }
    
    headers = {"User-Agent": "CyberScribe-Threat-Agent/1.0"}
    test_component = "python"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={test_component}&resultsPerPage=3"
    
    try:
        start_t = time.time()
        res = requests.get(url, headers=headers, timeout=15)
        elapsed = round(time.time() - start_t, 2)
        results["http_status"] = res.status_code
        print(f"  -> Request URL: {url}")
        print(f"  -> HTTP Status: {res.status_code} (took {elapsed}s)")
        
        if res.status_code == 200:
            results["connection_success"] = True
            data = res.json()
            vulns = data.get("vulnerabilities", [])
            results["entry_count"] = len(vulns)
            results["content_returned"] = len(vulns) > 0
            print(f"  -> Returned {len(vulns)} vulnerability records")
            
            if vulns:
                first_cve = vulns[0].get("cve", {})
                cve_id = first_cve.get("id")
                pub_str = first_cve.get("published")
                print(f"  -> Sample CVE ID: {cve_id}")
                print(f"  -> Raw published timestamp: '{pub_str}'")
                
                if pub_str:
                    try:
                        clean_pub = pub_str.replace("Z", "").split(".")[0]
                        pub_dt = datetime.fromisoformat(clean_pub)
                        results["pub_date_extracted"] = True
                        results["pub_date_sample"] = str(pub_dt)
                        print(f"  -> Parsed ISO published_at: {pub_dt}")
                    except Exception as parse_err:
                        print(f"  -> Failed to parse published timestamp: {parse_err}")
                
                # Test duplicate detection against database
                source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                existing = db.query(models.ThreatReport).filter(
                    (models.ThreatReport.source_url == source_url) | (models.ThreatReport.cve_id == cve_id)
                ).first()
                results["duplicate_detection"] = True
                print(f"  -> Duplicate detection query result for {cve_id}: {'Found in DB (ID: ' + str(existing.id) + ')' if existing else 'New item (Not yet in DB)'}")
        else:
            results["error"] = f"HTTP {res.status_code}: {res.text[:150]}"
            print(f"  ❌ NVD request failed with status {res.status_code}")
    except Exception as e:
        results["error"] = str(e)
        print(f"  ❌ NVD connection error: {e}")
    finally:
        db.close()
        
    return results

def audit_feed(source_name: str, feed_url: str):
    print("\n" + "="*50)
    print(f"AUDITING FEED: {source_name}")
    print(f"URL: {feed_url}")
    print("="*50)
    
    db = SessionLocal()
    results = {
        "source": source_name,
        "type": "RSS/XML Feed",
        "url": feed_url,
        "http_status": None,
        "connection_success": False,
        "content_returned": False,
        "entry_count": 0,
        "pub_date_extracted": False,
        "pub_date_sample": None,
        "pub_date_raw": None,
        "actionability_results": [],
        "duplicate_detection": False,
        "error": None
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 CyberScribe/1.0"
    }
    
    # 1. Test Raw HTTP Request
    try:
        start_t = time.time()
        res = requests.get(feed_url, headers=headers, timeout=15)
        elapsed = round(time.time() - start_t, 2)
        results["http_status"] = res.status_code
        print(f"  -> Direct HTTP Status: {res.status_code} (took {elapsed}s, {len(res.content)} bytes)")
    except Exception as http_err:
        print(f"  -> Direct HTTP check failed: {http_err}")
        results["error"] = f"HTTP check error: {http_err}"
        
    # 2. Test Feedparser parsing
    try:
        # Feedparser with headers
        feed = feedparser.parse(feed_url, request_headers=headers)
        
        # Check bozo (feedparser XML malformed flag)
        bozo = getattr(feed, 'bozo', 0)
        bozo_exc = getattr(feed, 'bozo_exception', None)
        status = getattr(feed, 'status', results["http_status"])
        results["http_status"] = status
        
        entries = feed.entries
        results["entry_count"] = len(entries)
        print(f"  -> Feedparser status: {status}, bozo={bozo} (exc: {bozo_exc})")
        print(f"  -> Parsed entries count: {len(entries)}")
        
        if len(entries) > 0:
            results["connection_success"] = True
            results["content_returned"] = True
            
            # Analyze top 3 entries
            for idx, entry in enumerate(entries[:3]):
                title = entry.get("title", "No Title")
                summary = entry.get("summary", "")
                link = entry.get("link", "")
                raw_text = f"{title}: {summary}"
                
                # Check publication date
                has_pub = hasattr(entry, 'published_parsed') and entry.published_parsed is not None
                pub_dt = None
                raw_pub = entry.get("published") or entry.get("pubDate") or entry.get("updated")
                if has_pub:
                    try:
                        pub_dt = datetime(*entry.published_parsed[:6])
                    except Exception as pe:
                        pub_dt = None
                
                # Check Actionability filter
                is_actionable = any(kw in raw_text.lower() for kw in ACTIONABLE_KEYWORDS)
                
                # Check Duplicate Detection
                existing = db.query(models.ThreatReport).filter(models.ThreatReport.source_url == link).first()
                is_duplicate = existing is not None
                
                results["actionability_results"].append({
                    "title": title[:60],
                    "has_pub": has_pub,
                    "pub_dt": str(pub_dt) if pub_dt else None,
                    "raw_pub": str(raw_pub),
                    "is_actionable": is_actionable,
                    "is_duplicate": is_duplicate
                })
                
                if idx == 0:
                    results["pub_date_extracted"] = has_pub
                    results["pub_date_sample"] = str(pub_dt) if pub_dt else None
                    results["pub_date_raw"] = str(raw_pub)
                
                print(f"    [Item {idx+1}] Title: {title[:50]}...")
                print(f"              Published: {pub_dt} (raw: '{raw_pub}')")
                print(f"              Actionable: {is_actionable} | Duplicate in DB: {is_duplicate}")
                
            results["duplicate_detection"] = True
        else:
            if not results["error"]:
                results["error"] = f"0 entries returned (feed status: {status})"
            print(f"  ⚠️ 0 entries returned from {source_name}")
            
    except Exception as parse_err:
        results["error"] = str(parse_err)
        print(f"  ❌ Error parsing feed: {parse_err}")
    finally:
        db.close()
        
    return results

def audit_rag_and_analyst():
    print("\n" + "="*50)
    print("AUDITING RAG RETRIEVAL & ANALYST AGENT CONTEXT")
    print("="*50)
    rag_results = {}
    try:
        count = threat_collection.count()
        rag_results["chroma_doc_count"] = count
        print(f"  ✓ ChromaDB Total Vector Count: {count}")
        
        # Test semantic similarity retrieval for common security query
        query_text = "Apache Struts remote code execution vulnerability"
        search_res = threat_collection.query(
            query_texts=[query_text],
            n_results=3
        )
        
        docs = search_res.get("documents", [[]])[0]
        metas = search_res.get("metadatas", [[]])[0]
        distances = search_res.get("distances", [[]])[0] if search_res.get("distances") else []
        
        print(f"\n  -> Semantic search test query: '{query_text}'")
        print(f"  -> Retrieved {len(docs)} nearest matching threat embeddings:")
        for i, (doc, meta) in enumerate(zip(docs, metas)):
            dist = distances[i] if i < len(distances) else "N/A"
            print(f"     [{i+1}] ID: {meta.get('threat_id') or 'N/A'} | Severity: {meta.get('severity')} | Dist: {dist}")
            print(f"         Published At: {meta.get('published_at') or 'N/A'}")
            print(f"         Snippet: {doc.replace(chr(10), ' ')[:100]}...")
            
        # Test formatting used by Analyst agent
        similar_items = query_similar_threats(query_text, n_results=2)
        formatted_context = format_retrieved_threats_for_prompt(similar_items)
        print(f"\n  -> Context generated for Analyst Agent prompt:\n{formatted_context}")
        rag_results["analyst_context_generated"] = bool(formatted_context and "No historical" not in formatted_context)
        rag_results["status"] = "WORKING"
    except Exception as e:
        rag_results["status"] = "BROKEN"
        rag_results["error"] = str(e)
        print(f"  ❌ RAG verification failed: {e}")
        
    return rag_results

if __name__ == "__main__":
    feed_results = []
    
    # 1. Audit NVD
    nvd_res = audit_nvd_source()
    feed_results.append(nvd_res)
    
    # 2. Audit All Feeds in OSINT_FEEDS
    for name, url in OSINT_FEEDS.items():
        res = audit_feed(name, url)
        feed_results.append(res)
        time.sleep(1.0)
        
    # 3. Audit RAG & Analyst Agent
    rag_res = audit_rag_and_analyst()
    
    print("\n" + "="*50)
    print("SUMMARY AUDIT DATA (JSON)")
    print("="*50)
    import json
    print(json.dumps({"sources": feed_results, "rag": rag_res}, indent=2))
