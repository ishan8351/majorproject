"""
Hybrid GraphRAG Retriever for RegRadar.

Combines lexical BM25 keyword search over statutory descriptions and controls
with multi-hop graph traversal across standards, requirements, and cloud resources.
"""

import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from regradar.knowledge.graph import RegulatoryKnowledgeGraph
from regradar.knowledge.models import (
    CloudResourceNode,
    ControlNode,
    RegulatoryContext,
    RemediationRule,
    RequirementNode,
    StandardNode,
)


def _tokenize(text: str) -> List[str]:
    """
    Tokenizes text into lowercase terms, splitting on whitespace and punctuation,
    while keeping full alphanumeric terms and subwords.
    """
    raw_tokens = re.findall(r"[a-zA-Z0-9_\-\.]+", text.lower())
    tokens: List[str] = []
    for token in raw_tokens:
        tokens.append(token)
        # Also split hyphenated and underscored terms for subword recall
        subwords = re.split(r"[-_.]+", token)
        if len(subwords) > 1:
            tokens.extend([s for s in subwords if s])
    return tokens


class BM25Index:
    """
    In-memory Okapi BM25 lexical index.
    """

    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.doc_ids: List[str] = []
        self.doc_lengths: Dict[str, int] = {}
        self.avg_doc_length: float = 0.0
        self.doc_term_freqs: Dict[str, Dict[str, int]] = {}
        self.df: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.total_docs: int = 0

    def index(self, corpus: Dict[str, str]) -> None:
        """Indexes a dictionary mapping doc_id -> raw document text."""
        self.doc_ids = list(corpus.keys())
        self.total_docs = len(self.doc_ids)
        total_len = 0

        self.doc_term_freqs.clear()
        self.doc_lengths.clear()
        self.df.clear()
        self.idf.clear()

        for doc_id, text in corpus.items():
            tokens = _tokenize(text)
            self.doc_lengths[doc_id] = len(tokens)
            total_len += len(tokens)

            tf: Dict[str, int] = {}
            for t in tokens:
                tf[t] = tf.get(t, 0) + 1
            self.doc_term_freqs[doc_id] = tf

            for t in tf.keys():
                self.df[t] = self.df.get(t, 0) + 1

        self.avg_doc_length = (total_len / self.total_docs) if self.total_docs > 0 else 0.0

        # Compute IDF
        for term, freq in self.df.items():
            # Standard Okapi IDF with floor
            idf_val = math.log(((self.total_docs - freq + 0.5) / (freq + 0.5)) + 1.0)
            self.idf[term] = max(0.01, idf_val)

    def score(self, query: str) -> Dict[str, float]:
        """Calculates BM25 scores for each document against the query."""
        tokens = _tokenize(query)
        scores: Dict[str, float] = {doc_id: 0.0 for doc_id in self.doc_ids}

        for token in tokens:
            if token not in self.idf:
                continue
            token_idf = self.idf[token]

            for doc_id in self.doc_ids:
                tf = self.doc_term_freqs[doc_id].get(token, 0)
                if tf == 0:
                    continue
                doc_len = self.doc_lengths[doc_id]
                num = tf * (self.k1 + 1.0)
                denom = tf + self.k1 * (1.0 - self.b + self.b * (doc_len / self.avg_doc_length))
                scores[doc_id] += token_idf * (num / denom)

        return scores


class HybridGraphRAGRetriever:
    """
    Hybrid GraphRAG retriever that unites lexical search across statute text
    and structured ontological multi-hop traversal in the Knowledge Graph.
    """

    def __init__(self, graph: Optional[RegulatoryKnowledgeGraph] = None):
        self.graph = graph or RegulatoryKnowledgeGraph()
        self._rule_index = BM25Index()
        self._control_index = BM25Index()
        self._standard_index = BM25Index()
        self._req_index = BM25Index()
        self._resource_index = BM25Index()
        self._build_indexes()

    def _build_indexes(self) -> None:
        """Builds separate BM25 indexes for each ontological node type."""
        # 1. Rule Index
        rule_corpus: Dict[str, str] = {}
        for rule in self.graph.get_rules():
            text = (
                f"{rule.check_id} {rule.name} {rule.description} "
                f"{rule.statute_reference} {rule.resource_type} {rule.framework} "
                f"{' '.join(rule.validation_rules)}"
            )
            rule_corpus[rule.check_id] = text
        self._rule_index.index(rule_corpus)

        # 2. Control Index
        control_corpus: Dict[str, str] = {}
        for ctrl in self.graph.get_controls():
            text = (
                f"{ctrl.id} {ctrl.control_id} {ctrl.title} {ctrl.description} "
                f"{ctrl.family or ''} {ctrl.standard_id}"
            )
            control_corpus[ctrl.id] = text
        self._control_index.index(control_corpus)

        # 3. Standard Index
        std_corpus: Dict[str, str] = {}
        for std in self.graph.get_standards():
            text = (
                f"{std.id} {std.name} {std.description} "
                f"{std.version or ''} {std.jurisdiction or ''}"
            )
            std_corpus[std.id] = text
        self._standard_index.index(std_corpus)

        # 4. Requirement Index
        req_corpus: Dict[str, str] = {}
        for req in self.graph.get_requirements():
            text = f"{req.id} {req.name} {req.description} {req.category or ''}"
            req_corpus[req.id] = text
        self._req_index.index(req_corpus)

        # 5. Resource Index
        res_corpus: Dict[str, str] = {}
        for res in self.graph.get_resources():
            text = (
                f"{res.id} {res.resource_type} {res.cloud_provider} "
                f"{res.service} {res.description or ''}"
            )
            res_corpus[res.id] = text
        self._resource_index.index(res_corpus)

    def retrieve(
        self,
        query: str,
        resource_type: Optional[str] = None,
        top_k: int = 3,
    ) -> List[RegulatoryContext]:
        """
        Executes hybrid retrieval:
          1. Computes BM25 lexical similarity scores for Rules, Controls, Standards,
             Requirements, and Resources.
          2. Traverses multi-hop graph edges (MANDATES, REQUIRES_CONTROL, APPLIES_TO_RESOURCE,
             REMEDIATED_BY) to propagate relevance from high-scoring ontology seeds to candidate rules.
          3. Applies resource type affinity filtering and boosting.
          4. Returns top_k enriched RegulatoryContext objects with structured statutory basis.
        """
        # 1. Lexical Scoring
        rule_scores = self._rule_index.score(query)
        ctrl_scores = self._control_index.score(query)
        std_scores = self._standard_index.score(query)
        req_scores = self._req_index.score(query)
        res_scores = self._resource_index.score(query)

        # Decay factors for multi-hop propagation
        HOP_1_DECAY = 0.55
        HOP_2_DECAY = 0.35

        candidate_scores: Dict[str, float] = {}
        rationales: Dict[str, List[str]] = {}

        # 2. Base Lexical Scores on Rules
        for check_id, score in rule_scores.items():
            candidate_scores[check_id] = score
            rationales[check_id] = []
            if score > 0.0:
                rationales[check_id].append(f"direct lexical match on rule text (BM25: {score:.2f})")

        # 3. Multi-Hop Propagation from Controls (Control -> REMEDIATED_BY -> Rule)
        for ctrl_id, score in ctrl_scores.items():
            if score <= 0.0:
                continue
            ctrl_key = f"control:{ctrl_id}"
            if not self.graph.raw_graph.has_node(ctrl_key):
                continue
            for succ in self.graph.raw_graph.successors(ctrl_key):
                succ_data = self.graph.raw_graph.nodes[succ]
                if succ_data.get("type") == "rule":
                    check_id = succ_data["id"]
                    boost = score * HOP_1_DECAY
                    candidate_scores[check_id] = candidate_scores.get(check_id, 0.0) + boost
                    rationales.setdefault(check_id, []).append(
                        f"1-hop graph traversal from Control '{ctrl_id}' (+{boost:.2f})"
                    )

        # 4. Multi-Hop Propagation from Requirements (Requirement -> REMEDIATED_BY -> Rule)
        for req_id, score in req_scores.items():
            if score <= 0.0:
                continue
            req_key = f"requirement:{req_id}"
            if not self.graph.raw_graph.has_node(req_key):
                continue
            for succ in self.graph.raw_graph.successors(req_key):
                succ_data = self.graph.raw_graph.nodes[succ]
                if succ_data.get("type") == "rule":
                    check_id = succ_data["id"]
                    boost = score * HOP_1_DECAY
                    candidate_scores[check_id] = candidate_scores.get(check_id, 0.0) + boost
                    rationales.setdefault(check_id, []).append(
                        f"1-hop graph traversal from Requirement '{req_id}' (+{boost:.2f})"
                    )

        # 5. Multi-Hop Propagation from Standards (Standard -> MANDATES -> Control -> Rule)
        for std_id, score in std_scores.items():
            if score <= 0.0:
                continue
            std_key = f"standard:{std_id}"
            if not self.graph.raw_graph.has_node(std_key):
                continue
            for ctrl_node in self.graph.raw_graph.successors(std_key):
                if not self.graph.raw_graph.has_node(ctrl_node):
                    continue
                for rule_node in self.graph.raw_graph.successors(ctrl_node):
                    rule_data = self.graph.raw_graph.nodes[rule_node]
                    if rule_data.get("type") == "rule":
                        check_id = rule_data["id"]
                        boost = score * HOP_2_DECAY
                        candidate_scores[check_id] = candidate_scores.get(check_id, 0.0) + boost
                        rationales.setdefault(check_id, []).append(
                            f"2-hop graph traversal from Standard '{std_id}' (+{boost:.2f})"
                        )

        # 6. Propagation from Resources (Resource -> APPLIES_TO_RESOURCE (reverse) -> Rule)
        for res_id, score in res_scores.items():
            if score <= 0.0:
                continue
            res_key = f"resource:{res_id}"
            if not self.graph.raw_graph.has_node(res_key):
                continue
            for pred in self.graph.raw_graph.predecessors(res_key):
                pred_data = self.graph.raw_graph.nodes[pred]
                if pred_data.get("type") == "rule":
                    check_id = pred_data["id"]
                    boost = score * HOP_1_DECAY
                    candidate_scores[check_id] = candidate_scores.get(check_id, 0.0) + boost
                    rationales.setdefault(check_id, []).append(
                        f"1-hop graph link to Resource '{res_id}' (+{boost:.2f})"
                    )

        # 7. Target Resource Affinity Filtering & Boosting
        final_scores: Dict[str, float] = {}
        for check_id, score in candidate_scores.items():
            rule = self.graph.find_remediation(check_id)
            if not rule:
                continue

            if resource_type:
                if rule.resource_type == resource_type:
                    # Target resource matches: boost score significantly
                    boosted = (score + 1.0) * 2.0
                    final_scores[check_id] = boosted
                    rationales[check_id].append(
                        f"target resource match on '{resource_type}' (2.0x boost)"
                    )
                else:
                    # Target resource does not match: exclude when explicit resource_type is provided
                    continue
            else:
                if score > 0.0:
                    final_scores[check_id] = score

        # 8. Sort and assemble top_k RegulatoryContext
        sorted_candidates = sorted(
            final_scores.items(), key=lambda item: item[1], reverse=True
        )[:top_k]

        results: List[RegulatoryContext] = []
        for check_id, score in sorted_candidates:
            rule = self.graph.find_remediation(check_id)
            if not rule:
                continue
            basis = self.graph.get_statutory_basis(check_id)
            standards = [s.name for s in basis.standards] if basis else [rule.framework]
            controls = basis.controls if basis else []
            requirements = basis.requirements if basis else []

            rationale_text = "; ".join(rationales.get(check_id, []))
            if not rationale_text:
                rationale_text = "Retrieved via composite graph ranking."

            results.append(
                RegulatoryContext(
                    check_id=check_id,
                    rule=rule,
                    resource_type=rule.resource_type,
                    standards=standards,
                    controls=controls,
                    requirements=requirements,
                    score=round(score, 4),
                    rationale=rationale_text,
                )
            )

        return results
