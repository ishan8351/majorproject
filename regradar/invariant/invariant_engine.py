from typing import Any, Dict, List, Optional, Set

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
        """
        Deep diff between before and after states. Handles deeply nested maps,
        lists, and blocks (e.g., tags, ingress/egress rule blocks).
        """
        if not before or not after:
            return []

        modified: List[str] = []

        def _recurse_modified(b_val: Any, a_val: Any, prefix: str = ""):
            # Both are dicts (e.g. nested blocks, maps, tags)
            if isinstance(b_val, dict) and isinstance(a_val, dict):
                all_keys = sorted(set(b_val.keys()).union(a_val.keys()))
                for k in all_keys:
                    subpath = f"{prefix}.{k}" if prefix else k
                    if k not in b_val or k not in a_val:
                        modified.append(subpath)
                    else:
                        _recurse_modified(b_val[k], a_val[k], subpath)
            # Both are lists (e.g. repeated rule blocks, ingress/egress lists)
            elif isinstance(b_val, list) and isinstance(a_val, list):
                min_len = min(len(b_val), len(a_val))
                for i in range(min_len):
                    subpath = f"{prefix}[{i}]" if prefix else f"[{i}]"
                    _recurse_modified(b_val[i], a_val[i], subpath)
                for i in range(min_len, len(b_val)):
                    subpath = f"{prefix}[{i}]" if prefix else f"[{i}]"
                    modified.append(subpath)
                for i in range(min_len, len(a_val)):
                    subpath = f"{prefix}[{i}]" if prefix else f"[{i}]"
                    modified.append(subpath)
            else:
                if b_val != a_val:
                    if prefix:
                        modified.append(prefix)

        _recurse_modified(before, after, "")
        return sorted(list(set(modified)))

    def _find_dropped_attributes(
        self, before: Optional[Dict[str, Any]], after: Optional[Dict[str, Any]]
    ) -> List[str]:
        """
        Detects attributes that had values before but became None/empty after.
        Handles deeply nested maps, lists, and repeated blocks (e.g. tags, ingress/egress).
        """
        if not before or not after:
            return []

        dropped: List[str] = []

        def _is_empty_or_none(val: Any) -> bool:
            return val is None or val == "" or val == {} or val == []

        def _recurse_dropped(b_val: Any, a_val: Any, prefix: str = ""):
            if _is_empty_or_none(b_val):
                return

            # Check if whole value was nullified
            if a_val is None:
                if prefix:
                    dropped.append(prefix)
                return

            if isinstance(b_val, str):
                if b_val != "" and a_val == "":
                    if prefix:
                        dropped.append(prefix)
                return

            if isinstance(b_val, dict):
                if not isinstance(a_val, dict):
                    if prefix:
                        dropped.append(prefix)
                    return
                if len(b_val) > 0 and len(a_val) == 0:
                    if prefix:
                        dropped.append(prefix)
                    return
                for k, sub_b in b_val.items():
                    subpath = f"{prefix}.{k}" if prefix else k
                    if k not in a_val or a_val[k] is None:
                        if not _is_empty_or_none(sub_b):
                            dropped.append(subpath)
                    else:
                        _recurse_dropped(sub_b, a_val[k], subpath)
                return

            if isinstance(b_val, list):
                if not isinstance(a_val, list):
                    if prefix:
                        dropped.append(prefix)
                    return
                if len(b_val) > 0 and len(a_val) == 0:
                    if prefix:
                        dropped.append(prefix)
                    return
                # Elements that existed before but were truncated
                for i in range(len(a_val), len(b_val)):
                    subpath = f"{prefix}[{i}]" if prefix else f"[{i}]"
                    dropped.append(subpath)
                # Elements that exist in both: inspect nested contents
                for i in range(min(len(b_val), len(a_val))):
                    subpath = f"{prefix}[{i}]" if prefix else f"[{i}]"
                    _recurse_dropped(b_val[i], a_val[i], subpath)
                return

        _recurse_dropped(before, after, "")
        return sorted(list(set(dropped)))
