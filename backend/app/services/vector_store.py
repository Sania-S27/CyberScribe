# backend/app/services/vector_store.py
import logging
from typing import Optional, Any, Dict, List
from datetime import datetime
from app.core.chroma import threat_collection

logger = logging.getLogger(__name__)


def _sanitize_metadata_value(val: Any) -> str:
    """Ensures metadata value is compliant with ChromaDB types (str, int, float, bool)."""
    if val is None:
        return ""
    if isinstance(val, (str, int, float, bool)):
        return val
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


def add_threat_embedding(
    threat_id: str,
    title: str,
    summary: str,
    severity: str = "medium",
    source_url: Optional[str] = None,
    cve_id: Optional[str] = None,
    published_at: Optional[Any] = None
) -> bool:
    """
    Stores high-dimensional vector embeddings with provenance metadata for semantic similarity search.
    Uses upsert to prevent duplicates on re-ingestion.
    """
    if not threat_collection.is_available:
        logger.error(f"[-] [ChromaDB Error] Vector store is unavailable. Mutation bypassed for threat ID: {threat_id or cve_id}")
        return False

    try:
        if not title and not summary:
            logger.warning("[ChromaDB] Cannot index threat with empty title and summary.")
            return False

        doc_title = title or "Advisory"
        doc_summary = summary or ""
        document_text = f"Title: {doc_title}\nSummary: {doc_summary}"
        
        # Build sanitized metadata dictionary (only primitive types accepted by ChromaDB)
        metadata: Dict[str, Any] = {
            "threat_id": _sanitize_metadata_value(threat_id),
            "severity": _sanitize_metadata_value(severity).lower() if severity else "medium",
            "cve_id": _sanitize_metadata_value(cve_id),
            "source_url": _sanitize_metadata_value(source_url),
            "published_at": _sanitize_metadata_value(published_at)
        }
        
        doc_id = f"threat-{threat_id}" if threat_id else f"threat-{cve_id or doc_title[:20]}"

        threat_collection.upsert(
            documents=[document_text],
            metadatas=[metadata],
            ids=[doc_id]
        )
        print(f"[+] [ChromaDB] Indexed vector embedding for threat ID: {threat_id or cve_id}")
        return True
    except Exception as e:
        print(f"[-] [ChromaDB Error] Failed to store embedding for {threat_id or cve_id}: {e}")
        logger.error(f"Failed to upsert threat embedding to ChromaDB: {e}", exc_info=True)
        return False


def query_similar_threats(query_text: str, n_results: int = 3) -> Dict[str, List[Any]]:
    """
    Executes semantic similarity search over historical threat vectors.
    Safely handles empty queries, empty collections, and query exceptions.
    """
    default_empty: Dict[str, List[Any]] = {
        "ids": [[]],
        "documents": [[]],
        "metadatas": [[]],
        "distances": [[]]
    }
    
    if not query_text or not query_text.strip():
        return default_empty

    try:
        col_count = threat_collection.count()
        if col_count == 0:
            return default_empty

        fetch_k = min(n_results, col_count)
        results = threat_collection.query(
            query_texts=[query_text.strip()],
            n_results=fetch_k
        )
        return results if results else default_empty
    except Exception as e:
        print(f"[-] [ChromaDB Error] Query failed: {e}")
        logger.error(f"ChromaDB similarity search failed: {e}", exc_info=True)
        return default_empty


def format_retrieved_threats_for_prompt(results: Dict[str, Any]) -> str:
    """
    Formats ChromaDB similarity search results into structured text for the LLM RAG prompt,
    highlighting provenance metadata while clearly indicating when no results were found.
    """
    if not results or not results.get("documents") or not results["documents"][0]:
        return "No historical threat intelligence records found."

    docs = results["documents"][0]
    metas = results.get("metadatas", [[]])[0] if results.get("metadatas") else []

    formatted_entries = []
    for idx, doc in enumerate(docs):
        meta = metas[idx] if idx < len(metas) and isinstance(metas[idx], dict) else {}
        
        cve_id = meta.get("cve_id") or "N/A"
        severity = meta.get("severity") or "unknown"
        source_url = meta.get("source_url") or "N/A"
        published_at = meta.get("published_at") or "N/A"

        entry = (
            f"[Historical Precedent #{idx + 1}]\n"
            f"• CVE / Reference: {cve_id}\n"
            f"• Historical Severity: {severity}\n"
            f"• Source Provenance: {source_url}\n"
            f"• Published Date: {published_at}\n"
            f"• Details:\n{doc}"
        )
        formatted_entries.append(entry)

    return "\n\n".join(formatted_entries)