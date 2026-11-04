import logging
import chromadb
from chromadb.config import Settings as ChromaSettings
from app.core.config import settings

logger = logging.getLogger(__name__)

_chroma_client = None
_threat_collection = None


def get_chroma_client():
    global _chroma_client
    if _chroma_client is None:
        try:
            _chroma_client = chromadb.PersistentClient(
                path=settings.CHROMADB_PATH,
                settings=ChromaSettings(allow_reset=True, anonymized_telemetry=False),
                tenant="default_tenant",
                database="default_database"
            )
            logger.info(f"[ChromaDB Client] Initialized PersistentClient against path: {settings.CHROMADB_PATH}")
        except BaseException as e:
            logger.error(f"[ChromaDB Client Warning] Initialization failed for path '{settings.CHROMADB_PATH}': {e}", exc_info=True)
            return None
    return _chroma_client


def get_threat_collection():
    global _threat_collection
    if _threat_collection is None:
        try:
            client = get_chroma_client()
            if client is not None:
                _threat_collection = client.get_or_create_collection(
                    name="cyber_threat_intelligence",
                    metadata={"hnsw:space": "cosine"}
                )
                logger.info(f"[ChromaDB Collection] Attached to collection 'cyber_threat_intelligence' (count: {_threat_collection.count()})")
            else:
                logger.error("[ChromaDB Collection Error] Cannot acquire collection: PersistentClient is unavailable.")
                return None
        except BaseException as e:
            logger.error(f"[ChromaDB Collection Warning] Access failed: {e}", exc_info=True)
            return None
    return _threat_collection


# Alias for backward-compatibility and diagnostic tools
get_threat_intel_collection = get_threat_collection


class LazyThreatCollection:
    """Proxy object that safely delegates to Chroma collection or falls back if locked/unavailable."""

    @property
    def is_available(self) -> bool:
        """Returns True if the underlying ChromaDB collection is reachable and active."""
        return get_threat_collection() is not None

    def __getattr__(self, name):
        col = get_threat_collection()
        if col is not None:
            return getattr(col, name)
        
        # Fallback dummy methods for graceful offline/concurrency operation
        if name in ("upsert", "add", "delete", "update"):
            def dummy_mutate(*args, **kwargs):
                logger.error(f"[ChromaDB Fallback] Mutate '{name}' bypassed due to unavailable vector store.")
                raise RuntimeError(f"ChromaDB vector store is unavailable. Mutation '{name}' bypassed.")
            return dummy_mutate
        elif name == "query":
            def dummy_query(*args, **kwargs):
                logger.warning("[ChromaDB Fallback] Query bypassed due to unavailable vector store.")
                return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}
            return dummy_query
        elif name == "count":
            def dummy_count(*args, **kwargs):
                logger.warning("[ChromaDB Fallback] Count bypassed due to unavailable vector store.")
                return 0
            return dummy_count
        elif name == "get":
            def dummy_get(*args, **kwargs):
                logger.warning("[ChromaDB Fallback] Get bypassed due to unavailable vector store.")
                return {"ids": [], "documents": [], "metadatas": []}
            return dummy_get
            
        raise AttributeError(f"'LazyThreatCollection' has no attribute '{name}' and collection is unavailable.")


threat_collection = LazyThreatCollection()