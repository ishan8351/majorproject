from typing import Any, Dict, List, Optional, TYPE_CHECKING

from regradar.remediation.models import RemediationAction, RemediationStrategy

if TYPE_CHECKING:
    from regradar.knowledge.graph import RegulatoryKnowledgeGraph
    from regradar.knowledge.models import RegulatoryContext
    from regradar.knowledge.retriever import HybridGraphRAGRetriever


class _RulesDict(dict):
    """
    Lazy-loading dictionary that seamlessly proxies rule access to the
    expanded Ontological Catalog without causing circular import loops.
    """

    def __init__(self) -> None:
        super().__init__()
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            from regradar.knowledge.catalog import RULES as CATALOG_RULES
            for check_id, rule in CATALOG_RULES.items():
                super().__setitem__(check_id, rule.to_action())
            self._loaded = True

    def __getitem__(self, key: str) -> RemediationAction:
        self._ensure_loaded()
        return super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:
        self._ensure_loaded()
        return super().get(key, default)

    def keys(self):
        self._ensure_loaded()
        return super().keys()

    def values(self):
        self._ensure_loaded()
        return super().values()

    def items(self):
        self._ensure_loaded()
        return super().items()

    def __iter__(self):
        self._ensure_loaded()
        return super().__iter__()

    def __len__(self) -> int:
        self._ensure_loaded()
        return super().__len__()

    def __contains__(self, key: object) -> bool:
        self._ensure_loaded()
        return super().__contains__(key)


class RegulatoryKnowledgeBase:
    """
    Ontological knowledge base mapping statutory regulatory mandates (HIPAA, GDPR, NIST, PCI-DSS)
    to verifiable IaC configuration requirements and non-destructive remediation strategies.

    Backed by the multi-relational RegulatoryKnowledgeGraph and HybridGraphRAGRetriever.
    """

    _graph: Optional["RegulatoryKnowledgeGraph"] = None
    _retriever: Optional["HybridGraphRAGRetriever"] = None

    # Lazy-loading dictionary wrapping the expanded 30+ rule catalog
    RULES: Dict[str, RemediationAction] = _RulesDict()

    @classmethod
    def get_graph(cls) -> "RegulatoryKnowledgeGraph":
        """Retrieves or lazily instantiates the knowledge graph."""
        if cls._graph is None:
            from regradar.knowledge.graph import RegulatoryKnowledgeGraph
            cls._graph = RegulatoryKnowledgeGraph()
        return cls._graph

    @classmethod
    def get_retriever(cls) -> "HybridGraphRAGRetriever":
        """Retrieves or lazily instantiates the Hybrid GraphRAG retriever."""
        if cls._retriever is None:
            from regradar.knowledge.retriever import HybridGraphRAGRetriever
            cls._retriever = HybridGraphRAGRetriever(graph=cls.get_graph())
        return cls._retriever

    @classmethod
    def get_action_for_check(cls, check_id: str) -> Optional[RemediationAction]:
        """Retrieves verified non-destructive remediation action for a check ID."""
        return cls.RULES.get(check_id)

    @classmethod
    def get_supported_checks(cls) -> List[str]:
        """Returns all supported static check identifiers."""
        return list(cls.RULES.keys())

    @classmethod
    def query(
        cls,
        query: str,
        resource_type: Optional[str] = None,
        top_k: int = 3,
    ) -> List["RegulatoryContext"]:
        """Queries the underlying Hybrid GraphRAG Retriever."""
        return cls.get_retriever().retrieve(query=query, resource_type=resource_type, top_k=top_k)
