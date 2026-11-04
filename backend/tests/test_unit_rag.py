import unittest
from unittest.mock import patch, MagicMock
import os
import sys

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.chroma import threat_collection
from app.services.vector_store import (
    query_similar_threats,
    format_retrieved_threats_for_prompt,
    add_threat_embedding,
    _sanitize_metadata_value
)
from app.agents.analyst import analyze_threat_with_llm
from tests.base import BaseTestCase


class TestRAGPipeline(BaseTestCase):
    def test_chroma_collection_initialization_and_count(self):
        """Verifies ChromaDB collection initializes against persistent storage with 471+ records."""
        self.assertIsNotNone(threat_collection)
        self.assertEqual(threat_collection.name, "cyber_threat_intelligence")
        count = threat_collection.count()
        self.assertGreaterEqual(count, 471, "Collection must contain the historical baseline documents.")

    def test_query_similar_threats_retrieval(self):
        """Verifies semantic similarity retrieval finds relevant historical records."""
        results = query_similar_threats("Sendmail debug command vulnerability root execution", n_results=2)
        self.assertIn("documents", results)
        self.assertIn("metadatas", results)
        self.assertGreater(len(results["documents"][0]), 0)
        
        # Test formatting helper
        formatted = format_retrieved_threats_for_prompt(results)
        self.assertIn("[Historical Precedent #1]", formatted)
        self.assertIn("• Historical Severity:", formatted)
        self.assertIn("• Details:", formatted)

    def test_empty_and_failed_retrieval_handling(self):
        """Verifies robust behavior on empty query and retrieval failure."""
        # Empty query
        empty_res = query_similar_threats("")
        self.assertEqual(empty_res["documents"], [[]])
        
        # Format empty results
        empty_formatted = format_retrieved_threats_for_prompt(empty_res)
        self.assertEqual(empty_formatted, "No historical threat intelligence records found.")
        
        # Mocked ChromaDB exception
        with patch.object(threat_collection, "query", side_effect=Exception("ChromaDB connection timeout")):
            err_res = query_similar_threats("Test query with failing DB")
            self.assertEqual(err_res["documents"], [[]])
            err_formatted = format_retrieved_threats_for_prompt(err_res)
            self.assertEqual(empty_formatted, "No historical threat intelligence records found.")

    def test_analyst_agent_receives_retrieved_context_in_prompt(self):
        """Verifies that the Analyst Agent injects retrieved historical context into the LLM prompt."""
        from app.agents import analyst
        mock_llm_response = MagicMock()
        mock_llm_response.content = """```json
{
  "title": "Nginx Path Traversal Flaw",
  "summary": "Path traversal vulnerability allows unauthorized file access.",
  "severity": "high",
  "cve_id": "CVE-2026-1111",
  "mitre_mappings": [
    {
      "technique_id": "T1083",
      "technique_name": "File and Directory Discovery",
      "tactic": "discovery"
    }
  ]
}
```"""
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = mock_llm_response

        with patch.object(analyst, "analyst_chain", mock_chain):
            result = analyze_threat_with_llm("Nginx 1.25 unauthenticated path traversal disclosure")
            
            self.assertTrue(mock_chain.invoke.called)
            invoke_args = mock_chain.invoke.call_args[0][0]
            
            # Assert both prompt variables are passed
            self.assertIn("raw_text", invoke_args)
            self.assertIn("retrieved_context", invoke_args)
            self.assertIn("Nginx 1.25", invoke_args["raw_text"])
            self.assertIsInstance(invoke_args["retrieved_context"], str)
            
            # Verify parsed output
            self.assertEqual(result["title"], "Nginx Path Traversal Flaw")
            self.assertEqual(result["severity"], "high")
            self.assertEqual(result["cve_id"], "CVE-2026-1111")

    def test_analyst_agent_fallback_on_retrieval_error(self):
        """Verifies Analyst Agent does not crash and handles retrieval failure gracefully."""
        from app.agents import analyst
        mock_llm_response = MagicMock()
        mock_llm_response.content = """{
  "title": "Apache Struts RCE",
  "summary": "Remote code execution flaw in Apache Struts OGNL parser.",
  "severity": "critical",
  "cve_id": "CVE-2026-2222",
  "mitre_mappings": []
}"""
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = mock_llm_response

        with patch("app.agents.analyst.query_similar_threats", side_effect=RuntimeError("ChromaDB disk read error")), \
             patch.object(analyst, "analyst_chain", mock_chain):
            
            result = analyze_threat_with_llm("Apache Struts OGNL remote code execution")
            
            self.assertTrue(mock_chain.invoke.called)
            invoke_args = mock_chain.invoke.call_args[0][0]
            self.assertIn("No historical threat intelligence records found", invoke_args["retrieved_context"])
            self.assertEqual(result["cve_id"], "CVE-2026-2222")

    def test_vector_metadata_persistence_and_upsert(self):
        """Verifies adding and updating threat embeddings with rich metadata and idempotency."""
        test_id = "test-rag-9999"
        title = "Test Threat for Vector Ingestion"
        summary = "Comprehensive vulnerability summary for RAG indexing testing."
        severity = "high"
        source_url = "https://nvd.nist.gov/vuln/detail/CVE-2026-TEST"
        cve_id = "CVE-2026-TEST"
        
        try:
            # 1. Add embedding
            success = add_threat_embedding(
                threat_id=test_id,
                title=title,
                summary=summary,
                severity=severity,
                source_url=source_url,
                cve_id=cve_id
            )
            self.assertTrue(success)
            
            # 2. Retrieve the specific embedding
            fetched = threat_collection.get(ids=[f"threat-{test_id}"])
            self.assertEqual(len(fetched["ids"]), 1)
            self.assertEqual(fetched["metadatas"][0]["cve_id"], cve_id)
            self.assertEqual(fetched["metadatas"][0]["source_url"], source_url)
            self.assertEqual(fetched["metadatas"][0]["severity"], "high")

            # 3. Test upsert idempotency (updating severity)
            update_success = add_threat_embedding(
                threat_id=test_id,
                title=title,
                summary=summary,
                severity="critical",
                source_url=source_url,
                cve_id=cve_id
            )
            self.assertTrue(update_success)
            updated_fetch = threat_collection.get(ids=[f"threat-{test_id}"])
            self.assertEqual(len(updated_fetch["ids"]), 1)
            self.assertEqual(updated_fetch["metadatas"][0]["severity"], "critical")
        finally:
            # Clean up test document to keep historical collection clean
            try:
                threat_collection.delete(ids=[f"threat-{test_id}"])
            except Exception:
                pass

    def test_manual_ingestion_indexes_into_chromadb(self):
        """Verifies that POST /public/threats/ingest automatically triggers vector indexing."""
        ingest_payload = {
            "title": "OpenSSL Buffer Overflow RAG Ingestion Test",
            "cve_id": "CVE-2026-8888",
            "severity": "critical",
            "summary": "Heap buffer overflow in OpenSSL parsing routines allowing remote compromise.",
            "affected_software": ["openssl"]
        }
        
        with patch("app.api.threats.add_threat_embedding") as mock_add_embed:
            res = self.client.post("/public/threats/ingest", json=ingest_payload)
            self.assertEqual(res.status_code, 201)
            self.assertTrue(mock_add_embed.called)
            
            call_kwargs = mock_add_embed.call_args[1]
            self.assertEqual(call_kwargs["title"], ingest_payload["title"])
            self.assertEqual(call_kwargs["cve_id"], "CVE-2026-8888")
            self.assertEqual(call_kwargs["severity"], "critical")

    def test_chromadb_unavailable_mutation_raises_and_prevents_false_success(self):
        """Verifies that vector store unavailability prevents false success reports and raises on mutation bypass."""
        with patch("app.core.chroma.get_threat_collection", return_value=None):
            self.assertFalse(threat_collection.is_available)
            
            # Proxy mutation must raise RuntimeError rather than silent bypass
            with self.assertRaises(RuntimeError):
                threat_collection.upsert(ids=["test-bypass-id"], documents=["test text"])

            # Service helper must return False and not falsely report success
            success = add_threat_embedding(
                threat_id="test-fail-cve",
                title="Vulnerability when DB offline",
                summary="Should never claim success if bypassed"
            )
            self.assertFalse(success, "add_threat_embedding must return False when ChromaDB is unavailable.")


if __name__ == "__main__":
    unittest.main()
