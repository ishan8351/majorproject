"""
Multi-Agent Closed-Loop Governance State Machine for RegRadar.

Implements the formal governance lifecycle:
AUDIT -> GRAPH_RAG_RETRIEVE -> PLAN -> SYNTHESIZE -> SANDBOX_SIMULATE -> SEMANTIC_VERIFY -> [ACCEPT | RETRY_WITH_FEEDBACK | ESCALATE]
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING
from pydantic import BaseModel, Field

from regradar.invariant.models import InvariantReport
from regradar.remediation.models import PatchProposal, RemediationTask

if TYPE_CHECKING:
    from regradar.knowledge.models import RegulatoryContext
    from regradar.invariant.semantic_verifier import SemanticVerificationResult


class RemediationState(str, Enum):
    """Formal states in the autonomous remediation governance lifecycle."""
    AUDIT = "AUDIT"
    GRAPH_RAG_RETRIEVE = "GRAPH_RAG_RETRIEVE"
    PLAN = "PLAN"
    SYNTHESIZE = "SYNTHESIZE"
    SANDBOX_SIMULATE = "SANDBOX_SIMULATE"
    SEMANTIC_VERIFY = "SEMANTIC_VERIFY"
    ACCEPT = "ACCEPT"
    RETRY_WITH_FEEDBACK = "RETRY_WITH_FEEDBACK"
    ESCALATE = "ESCALATE"


class StateTransition(BaseModel):
    """Audit log entry capturing a verified state machine transition."""
    from_state: RemediationState
    to_state: RemediationState
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    message: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal state transition is attempted."""
    pass


# Directed transition graph enforcing strict governance flow
VALID_TRANSITIONS: Dict[RemediationState, Set[RemediationState]] = {
    RemediationState.AUDIT: {
        RemediationState.GRAPH_RAG_RETRIEVE,
        RemediationState.PLAN,  # direct shortcut when regulatory context is pre-loaded
        RemediationState.ESCALATE,
    },
    RemediationState.GRAPH_RAG_RETRIEVE: {
        RemediationState.PLAN,
        RemediationState.ESCALATE,
    },
    RemediationState.PLAN: {
        RemediationState.SYNTHESIZE,
        RemediationState.ESCALATE,
    },
    RemediationState.SYNTHESIZE: {
        RemediationState.SANDBOX_SIMULATE,
        RemediationState.ESCALATE,
    },
    RemediationState.SANDBOX_SIMULATE: {
        RemediationState.SEMANTIC_VERIFY,
        RemediationState.RETRY_WITH_FEEDBACK,
        RemediationState.ESCALATE,
    },
    RemediationState.SEMANTIC_VERIFY: {
        RemediationState.ACCEPT,
        RemediationState.RETRY_WITH_FEEDBACK,
        RemediationState.ESCALATE,
    },
    RemediationState.RETRY_WITH_FEEDBACK: {
        RemediationState.SYNTHESIZE,
        RemediationState.ESCALATE,
    },
    RemediationState.ACCEPT: set(),  # Terminal state
    RemediationState.ESCALATE: set(),  # Terminal state
}


class RemediationContext(BaseModel):
    """
    Mutable execution context tracking the lifecycle of an individual remediation task.
    """
    task: RemediationTask
    current_state: RemediationState = RemediationState.AUDIT
    history: List[StateTransition] = Field(default_factory=list)
    regulatory_context: Optional[Any] = None
    patch_proposal: Optional[PatchProposal] = None
    invariant_report: Optional[InvariantReport] = None
    semantic_result: Optional[Any] = None
    attempt_count: int = 0
    max_retries: int = 3
    feedback_history: List[str] = Field(default_factory=list)

    @property
    def is_terminal(self) -> bool:
        """Returns True if the task has concluded in ACCEPT or ESCALATE."""
        return self.current_state in (RemediationState.ACCEPT, RemediationState.ESCALATE)

    @property
    def is_accepted(self) -> bool:
        """Returns True if the patch was successfully verified and accepted."""
        return self.current_state == RemediationState.ACCEPT

    @property
    def is_escalated(self) -> bool:
        """Returns True if the task required human escalation."""
        return self.current_state == RemediationState.ESCALATE

    def can_retry(self) -> bool:
        """Determines whether another remediation attempt is allowed under policy."""
        return self.attempt_count < self.max_retries

    def record_feedback(self, feedback: str) -> None:
        """Records diagnostic supervisor feedback for patch refinement."""
        if feedback and feedback not in self.feedback_history:
            self.feedback_history.append(feedback)


class SwarmStateMachine:
    """
    Governance coordinator enforcing valid state transitions across the multi-agent swarm.
    """

    @classmethod
    def is_valid_transition(cls, from_state: RemediationState, to_state: RemediationState) -> bool:
        """Checks if a transition from from_state to to_state is valid."""
        allowed = VALID_TRANSITIONS.get(from_state, set())
        return to_state in allowed

    @classmethod
    def transition(
        cls,
        context: RemediationContext,
        next_state: RemediationState,
        message: str = "",
        **metadata: Any,
    ) -> StateTransition:
        """
        Executes a transition on the provided RemediationContext, logging the transition audit.
        Raises InvalidStateTransitionError if the transition violates the governance graph.
        """
        current = context.current_state
        if not cls.is_valid_transition(current, next_state):
            raise InvalidStateTransitionError(
                f"Invalid state transition: Cannot transition from '{current.value}' to '{next_state.value}'. "
                f"Allowed destinations: {[s.value for s in VALID_TRANSITIONS.get(current, set())]}"
            )

        transition_entry = StateTransition(
            from_state=current,
            to_state=next_state,
            message=message,
            metadata=metadata,
        )
        context.history.append(transition_entry)
        context.current_state = next_state

        if next_state == RemediationState.SYNTHESIZE:
            context.attempt_count += 1

        return transition_entry
