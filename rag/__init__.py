from rag.retrieve import retrieve, retrieve_rich, retrieve_for_cwe, retrieve_for_owasp
import rag.schemas as _schemas

_schemas.retrieve = retrieve


def init() -> None:
    """
    Explicit init call — alternative to relying on the import-time patch.
    Call this at the top of your agent file if you want to be explicit:

        import rag
        rag.init()
    """
    _schemas.retrieve = retrieve


__all__ = ["retrieve", "retrieve_rich", "retrieve_for_cwe", "retrieve_for_owasp", "init"]
