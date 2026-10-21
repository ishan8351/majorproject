from typing import Any, Dict, List, Set

from regradar.invariant.models import (
    InvariantReport,
    InvariantViolation,
    ResourceChange,
    ViolationType,
)


class InvariantEngine:
    """
    Deterministic rule engine enforcing the Zero-Destruction Invariant on IaC plan diffs.
    Guarantees:
      1. Zero deletions (no resources destroyed).
      2. Zero forced replacements (no destroy-and-recreate cycles).
      3. No silent dropping of critical schema configurations.
    """

    def __init__(self, allow_additive_creations: bool = True):
        self.allow_additive_creations = allow_additive_creations

    def verify(self, changes: List[ResourceChange]) -> InvariantReport:
        """Evaluates all planned changes against invariant rules."""
        violations: List[InvariantViolation] = []

        count_no_op = 0
        count_created = 0
        count_updated = 0
        count_deleted = 0
        count_replaced = 0

        for change in changes:
            # Action tallying
            if change.actions == ["no-op"]:
                count_no_op += 1
                continue

            if change.is_replace:
                count_replaced += 1
                diff_attrs = self._find_modified_attributes(change.before, change.after)
                violations.append(
                    InvariantViolation(
                        resource_address=change.address,
                        violation_type=ViolationType.FORCES_REPLACEMENT,
                        actions=change.actions,
                        action_reason=change.action_reason,
                        message=(
                            f"Resource '{change.address}' triggers FORCES REPLACEMENT (destroy and recreate). "
                            f"Action reason: {change.action_reason or 'Attribute modification requires replacement'}. "
                            f"Modified attributes: {', '.join(diff_attrs) if diff_attrs else 'unknown'}."
                        ),
                        problematic_attributes=diff_attrs,
                    )
                )
                continue

            if change.is_delete:
                count_deleted += 1
                violations.append(
                    InvariantViolation(
                        resource_address=change.address,
                        violation_type=ViolationType.UNINTENDED_DELETION,
                        actions=change.actions,
                        action_reason=change.action_reason,
                        message=f"Resource '{change.address}' is scheduled for DELETION. Automated patches cannot drop infrastructure.",
                    )
                )
                continue

            if change.is_create:
                count_created += 1
                if not self.allow_additive_creations:
                    violations.append(
                        InvariantViolation(
                            resource_address=change.address,
                            violation_type=ViolationType.INVALID_STATE_MUTATION,
                            actions=change.actions,
                            message=f"Additive resource creation for '{change.address}' is prohibited under current policy.",
                        )
                    )
                continue

            if change.is_update:
                count_updated += 1
                # Check for schema drops (unintended nullification of previously defined attributes)
                dropped_keys = self._find_dropped_attributes(change.before, change.after)
                if dropped_keys:
                    violations.append(
                        InvariantViolation(
                            resource_address=change.address,
                            violation_type=ViolationType.SCHEMA_DROP,
                            actions=change.actions,
                            message=(
                                f"Resource '{change.address}' silently drops previously configured attributes: "
                                f"{', '.join(dropped_keys)}."
                            ),
                            problematic_attributes=dropped_keys,
                        )
                    )

        is_safe = (count_deleted == 0) and (count_replaced == 0) and (len(violations) == 0)

        return InvariantReport(
            is_safe=is_safe,
            zero_destruction_guarantee_met=is_safe,
            total_resources_evaluated=len(changes),
            count_no_op=count_no_op,
            count_created=count_created,
            count_updated=count_updated,
            count_deleted=count_deleted,
            count_replaced=count_replaced,
            violations=violations,
            changes=changes,
        )

    def _find_modified_attributes(
        self, before: Optional[Dict[str, Any]], after: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Identifies top-level attributes that changed between before and after states."""
        if not before or not after:
            return []

        modified = []
        all_keys = set(before.keys()).union(after.keys())
        for k in all_keys:
            if before.get(k) != after.get(k):
                modified.append(k)
        return sorted(modified)

    def _find_dropped_attributes(
        self, before: Optional[Dict[str, Any]], after: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Detects attributes that had values before but became None/empty after."""
        if not before or not after:
            return []

        dropped = []
        for k, v_before in before.items():
            if v_before is not None and v_before != "" and v_before != {} and v_before != []:
                v_after = after.get(k)
                if v_after is None or (v_after == "" and v_before != ""):
                    dropped.append(k)
        return sorted(dropped)
