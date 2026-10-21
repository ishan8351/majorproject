from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PlanAction(str, Enum):
    NO_OP = "no-op"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    READ = "read"


class ViolationType(str, Enum):
    """
    Types of Invariant Violations that threaten state continuity.
    """
    FORCES_REPLACEMENT = "FORCES_REPLACEMENT"
    UNINTENDED_DELETION = "UNINTENDED_DELETION"
    SCHEMA_DROP = "SCHEMA_DROP"
    INVALID_STATE_MUTATION = "INVALID_STATE_MUTATION"


class ResourceChange(BaseModel):
    """Represents a planned change to a single infrastructure resource."""
    address: str
    resource_type: str
    name: str
    actions: List[str]
    action_reason: Optional[str] = None
    before: Optional[Dict[str, Any]] = None
    after: Optional[Dict[str, Any]] = None
    after_unknown: Optional[Dict[str, Any]] = None

    @property
    def is_create(self) -> bool:
        return self.actions == ["create"]

    @property
    def is_update(self) -> bool:
        return self.actions == ["update"]

    @property
    def is_delete(self) -> bool:
        return "delete" in self.actions and "create" not in self.actions

    @property
    def is_replace(self) -> bool:
        # OpenTofu records replacement as ["delete", "create"] or ["create", "delete"]
        return ("delete" in self.actions and "create" in self.actions) or bool(
            self.action_reason and "replace" in self.action_reason.lower()
        )

    @property
    def is_destructive(self) -> bool:
        return self.is_delete or self.is_replace


class InvariantViolation(BaseModel):
    """Details of a broken safety invariant."""
    resource_address: str
    violation_type: ViolationType
    actions: List[str]
    message: str
    action_reason: Optional[str] = None
    problematic_attributes: List[str] = Field(default_factory=list)


class InvariantReport(BaseModel):
    """Summary of dry-run invariant verification."""
    is_safe: bool
    zero_destruction_guarantee_met: bool
    total_resources_evaluated: int
    count_no_op: int = 0
    count_created: int = 0
    count_updated: int = 0
    count_deleted: int = 0
    count_replaced: int = 0
    violations: List[InvariantViolation] = Field(default_factory=list)
    changes: List[ResourceChange] = Field(default_factory=list)
