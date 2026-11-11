"""
Semantic Invariant Verification Engine for RegRadar.

Validates that applied configuration patches not only preserve state continuity
(zero deletions and forced replacements), but also semantically satisfy security
and compliance requirements (e.g. verifying that encryption or TLS enforcement was
actually enacted in the planned `after` state) and introduce zero security regressions.
"""

from enum import Enum
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from pydantic import BaseModel, Field

from regradar.invariant.models import ResourceChange
from regradar.remediation.models import RemediationAction, RemediationStrategy, RemediationTask


class SemanticViolationType(str, Enum):
    """Types of semantic compliance and security violations."""
    UNMET_REQUIREMENT = "UNMET_REQUIREMENT"
    SECURITY_REGRESSION = "SECURITY_REGRESSION"
    INCOMPLETE_PATCH = "INCOMPLETE_PATCH"


class SemanticRequirement(BaseModel):
    """Specification of a semantic security requirement expected in plan state."""
    resource_type: Optional[str] = None  # e.g., "aws_s3_bucket"
    resource_address: Optional[str] = None  # e.g., "aws_s3_bucket.logs"
    attribute_path: str  # e.g., "server_side_encryption_configuration" or "tags.Compliance"
    expected_value: Optional[Any] = None  # Expected value or None (checks presence and truthiness)
    allow_additive_attachment: bool = True  # Can be satisfied by an attached additive resource
    additive_resource_type: Optional[str] = None  # e.g., "aws_s3_bucket_server_side_encryption_configuration"
    description: str = ""
    statute_reference: Optional[str] = None


class SemanticViolation(BaseModel):
    """Details of a semantic invariant failure or security regression."""
    resource_address: str
    violation_type: SemanticViolationType
    attribute_path: str
    message: str
    expected: Optional[Any] = None
    actual: Optional[Any] = None


class SemanticVerificationResult(BaseModel):
    """Summary of semantic invariant verification."""
    is_valid: bool
    requirements_satisfied: bool
    no_regressions: bool
    satisfied_requirements: List[str] = Field(default_factory=list)
    unmet_requirements: List[str] = Field(default_factory=list)
    regressions: List[str] = Field(default_factory=list)
    violations: List[SemanticViolation] = Field(default_factory=list)
    total_requirements_evaluated: int = 0
    total_changes_inspected: int = 0


# Known additive resource types that fulfill security requirements for target parent resources
ADDITIVE_SECURITY_RESOURCES: Dict[str, Dict[str, Any]] = {
    "server_side_encryption_configuration": {
        "aws_s3_bucket": {
            "additive_type": "aws_s3_bucket_server_side_encryption_configuration",
            "parent_attr": "bucket",
        }
    },
    "versioning": {
        "aws_s3_bucket": {
            "additive_type": "aws_s3_bucket_versioning",
            "parent_attr": "bucket",
        }
    },
    "public_access_block": {
        "aws_s3_bucket": {
            "additive_type": "aws_s3_bucket_public_access_block",
            "parent_attr": "bucket",
        }
    },
    "logging": {
        "aws_s3_bucket": {
            "additive_type": "aws_s3_bucket_logging",
            "parent_attr": "bucket",
        }
    },
}

# Known security attributes across cloud providers and their regression rules
# Format: attribute_name -> {
#   "insecure_values": [...],
#   "cannot_be_dropped": bool,
#   "description": str,
# }
KNOWN_SECURITY_ATTRIBUTES: Dict[str, Dict[str, Any]] = {
    # AWS
    "server_side_encryption_configuration": {
        "cannot_be_dropped": True,
        "description": "Server-side encryption configuration removed or nullified",
    },
    "encrypted": {
        "insecure_values": [False, "false", "0", 0],
        "cannot_be_dropped": True,
        "description": "Resource encryption disabled",
    },
    "kms_key_id": {
        "cannot_be_dropped": True,
        "description": "KMS key encryption removed or nullified",
    },
    "block_public_acls": {
        "insecure_values": [False, "false"],
        "cannot_be_dropped": True,
        "description": "S3 block public ACLs disabled",
    },
    "block_public_policy": {
        "insecure_values": [False, "false"],
        "cannot_be_dropped": True,
        "description": "S3 block public policy disabled",
    },
    "ignore_public_acls": {
        "insecure_values": [False, "false"],
        "cannot_be_dropped": True,
        "description": "S3 ignore public ACLs disabled",
    },
    "restrict_public_buckets": {
        "insecure_values": [False, "false"],
        "cannot_be_dropped": True,
        "description": "S3 restrict public buckets disabled",
    },
    "enable_key_rotation": {
        "insecure_values": [False, "false"],
        "cannot_be_dropped": True,
        "description": "KMS key automatic rotation disabled",
    },
    "deletion_protection": {
        "insecure_values": [False, "false"],
        "cannot_be_dropped": True,
        "description": "Deletion protection disabled",
    },
    # Azure
    "enable_https_traffic_only": {
        "insecure_values": [False, "false"],
        "cannot_be_dropped": True,
        "description": "Azure storage HTTPS traffic only disabled",
    },
    "allow_blob_public_access": {
        "insecure_values": [True, "true"],
        "description": "Azure storage blob public access enabled",
    },
    "public_network_access_enabled": {
        "insecure_values": [True, "true"],
        "description": "Public network access enabled on private resource",
    },
    "infrastructure_encryption_enabled": {
        "insecure_values": [False, "false"],
        "cannot_be_dropped": True,
        "description": "Infrastructure encryption disabled",
    },
    # GCP
    "uniform_bucket_level_access": {
        "insecure_values": [False, "false"],
        "cannot_be_dropped": True,
        "description": "GCP uniform bucket level access disabled",
    },
    "kms_key_name": {
        "cannot_be_dropped": True,
        "description": "GCP KMS key configuration dropped",
    },
    # Kubernetes
    "read_only_root_filesystem": {
        "insecure_values": [False, "false"],
        "cannot_be_dropped": True,
        "description": "Kubernetes read-only root filesystem disabled",
    },
    "allow_privilege_escalation": {
        "insecure_values": [True, "true"],
        "description": "Kubernetes privilege escalation permitted",
    },
    "run_as_non_root": {
        "insecure_values": [False, "false"],
        "cannot_be_dropped": True,
        "description": "Kubernetes run as non-root requirement disabled",
    },
}


def resolve_nested_attribute(data: Optional[Dict[str, Any]], path: str) -> Tuple[bool, Any]:
    """
    Extracts a value from a nested dictionary/list structure using dot and indexed notation.
    e.g. 'rule[0].apply_server_side_encryption_by_default.sse_algorithm' or 'tags.Compliance'.
    Returns (found: bool, value: Any).
    """
    if data is None or not isinstance(data, dict):
        return False, None

    # Tokenize path into keys and indices: e.g. "rule[0].status" -> ["rule", 0, "status"]
    tokens: List[Union[str, int]] = []
    # Split by dots first, then handle bracket indexing
    parts = path.split(".")
    for part in parts:
        if "[" in part and part.endswith("]"):
            base = part[: part.find("[")]
            if base:
                tokens.append(base)
            index_str = part[part.find("[") + 1 : -1]
            try:
                tokens.append(int(index_str))
            except ValueError:
                tokens.append(index_str)
        else:
            tokens.append(part)

    current: Any = data
    for token in tokens:
        if isinstance(token, int):
            if isinstance(current, list) and 0 <= token < len(current):
                current = current[token]
            else:
                return False, None
        elif isinstance(token, str):
            if isinstance(current, dict) and token in current:
                current = current[token]
            elif isinstance(current, list):
                # Try finding in list of block dicts
                found_in_list = False
                for item in current:
                    if isinstance(item, dict) and token in item:
                        current = item[token]
                        found_in_list = True
                        break
                if not found_in_list:
                    return False, None
            else:
                return False, None
        else:
            return False, None

    return True, current


def register_additive_security_resource(
    requirement_attr: str,
    parent_type: str,
    additive_type: str,
    parent_attr: str = "bucket",
) -> None:
    """Dynamically registers an additive security resource pattern."""
    ADDITIVE_SECURITY_RESOURCES.setdefault(requirement_attr, {})[parent_type] = {
        "additive_type": additive_type,
        "parent_attr": parent_attr,
    }


def register_security_attribute(
    attribute_name: str,
    cannot_be_dropped: bool = True,
    insecure_values: Optional[List[Any]] = None,
    description: str = "",
) -> None:
    """Dynamically registers a security attribute and its regression invariant."""
    entry: Dict[str, Any] = {
        "cannot_be_dropped": cannot_be_dropped,
        "description": description or f"Security attribute '{attribute_name}' modified",
    }
    if insecure_values is not None:
        entry["insecure_values"] = insecure_values
    KNOWN_SECURITY_ATTRIBUTES[attribute_name] = entry


class SemanticInvariantVerifier:
    """
    Validates semantic compliance and security guarantees across IaC plan diffs.
    Ensures patches actually satisfy remediation requirements in the 'after' state
    and prevents security regressions.
    """

    def __init__(
        self,
        check_regressions: bool = True,
        custom_additive_resources: Optional[Dict[str, Dict[str, Any]]] = None,
        custom_security_attributes: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.check_regressions = check_regressions
        self.additive_resources: Dict[str, Dict[str, Any]] = {
            k: dict(v) for k, v in ADDITIVE_SECURITY_RESOURCES.items()
        }
        if custom_additive_resources:
            for k, v in custom_additive_resources.items():
                self.additive_resources.setdefault(k, {}).update(v)

        self.security_attributes: Dict[str, Dict[str, Any]] = dict(KNOWN_SECURITY_ATTRIBUTES)
        if custom_security_attributes:
            self.security_attributes.update(custom_security_attributes)

        self.custom_regression_checks: List[Callable[[ResourceChange], List[SemanticViolation]]] = []

    def add_regression_check(
        self, check_fn: Callable[[ResourceChange], List[SemanticViolation]]
    ) -> None:
        """Registers a custom callback for checking regressions on resource changes."""
        self.custom_regression_checks.append(check_fn)

    def verify(
        self,
        changes: List[ResourceChange],
        requirements: Optional[List[SemanticRequirement]] = None,
    ) -> SemanticVerificationResult:
        """
        Executes semantic invariant verification on the provided plan changes.
        Validates all requirements against 'after' state and verifies no security
        regressions were introduced.
        """
        requirements = requirements or []
        satisfied_reqs: List[str] = []
        unmet_reqs: List[str] = []
        regressions: List[str] = []
        violations: List[SemanticViolation] = []

        # 1. Verify Semantic Requirements
        for req in requirements:
            req_name = req.description or f"{req.resource_address or req.resource_type}.{req.attribute_path}"
            is_satisfied, violation = self._verify_requirement(req, changes)
            if is_satisfied:
                satisfied_reqs.append(req_name)
            else:
                unmet_reqs.append(req_name)
                if violation:
                    violations.append(violation)

        # 2. Check for Security Regressions in Modified Resources
        if self.check_regressions:
            for change in changes:
                if change.actions in (["update"], ["no-op"]):
                    reg_violations = self._check_resource_regressions(change)
                    for rv in reg_violations:
                        regressions.append(f"{rv.resource_address}: {rv.message}")
                        violations.append(rv)

                # Run custom regression checks
                for custom_check in self.custom_regression_checks:
                    custom_violations = custom_check(change)
                    for cv in custom_violations:
                        regressions.append(f"{cv.resource_address}: {cv.message}")
                        violations.append(cv)

        reqs_met = len(unmet_reqs) == 0
        no_regs = len(regressions) == 0
        is_valid = reqs_met and no_regs

        return SemanticVerificationResult(
            is_valid=is_valid,
            requirements_satisfied=reqs_met,
            no_regressions=no_regs,
            satisfied_requirements=satisfied_reqs,
            unmet_requirements=unmet_reqs,
            regressions=regressions,
            violations=violations,
            total_requirements_evaluated=len(requirements),
            total_changes_inspected=len(changes),
        )

    def _verify_requirement(
        self, req: SemanticRequirement, changes: List[ResourceChange]
    ) -> Tuple[bool, Optional[SemanticViolation]]:
        """Verifies an individual semantic requirement against the plan changes."""
        # Find primary target resource change
        target_change: Optional[ResourceChange] = None
        for change in changes:
            if req.resource_address and change.address == req.resource_address:
                target_change = change
                break
            if not req.resource_address and req.resource_type and change.resource_type == req.resource_type:
                target_change = change
                break

        # Check in-place 'after' state on primary target resource
        if target_change and target_change.after:
            found, val = resolve_nested_attribute(target_change.after, req.attribute_path)
            if found:
                if self._value_matches_expected(val, req.expected_value):
                    return True, None

        # Check additive attachment if allowed
        if req.allow_additive_attachment:
            target_id = req.resource_address or (target_change.address if target_change else "")
            target_name = target_id.split(".")[-1] if target_id else ""
            clean_attr_key = req.attribute_path.split(".")[0].split("[")[0]

            for change in changes:
                if not change.is_create or not change.after:
                    continue

                # Check if this created resource is an additive security attachment
                is_match = False
                after_cfg = change.after

                # Direct additive_resource_type match
                if req.additive_resource_type and change.resource_type == req.additive_resource_type:
                    is_match = True

                # Check known additive resources table
                parent_info = self.additive_resources.get(clean_attr_key, {}).get(
                    req.resource_type or (target_change.resource_type if target_change else "")
                )
                if parent_info and change.resource_type == parent_info["additive_type"]:
                    parent_ref = after_cfg.get(parent_info["parent_attr"])
                    if parent_ref:
                        parent_str = str(parent_ref)
                        if target_name and (target_name in parent_str or target_id in parent_str):
                            is_match = True
                        elif not target_id:
                            is_match = True

                if is_match:
                    return True, None

        # If we reached here, requirement was not satisfied
        target_display = req.resource_address or req.resource_type or "resource"
        actual_val = None
        if target_change and target_change.after:
            _, actual_val = resolve_nested_attribute(target_change.after, req.attribute_path)

        msg = (
            f"Semantic requirement not satisfied for '{target_display}': "
            f"Attribute '{req.attribute_path}' expected '{req.expected_value or 'configured/enabled'}', "
            f"found '{actual_val}'."
        )
        if req.statute_reference:
            msg += f" (Statute: {req.statute_reference})"

        violation = SemanticViolation(
            resource_address=target_display,
            violation_type=SemanticViolationType.UNMET_REQUIREMENT,
            attribute_path=req.attribute_path,
            message=msg,
            expected=req.expected_value or "enabled",
            actual=actual_val,
        )
        return False, violation

    def _value_matches_expected(self, actual: Any, expected: Any) -> bool:
        """Compares actual value with expected value."""
        if expected is None:
            # Check presence and truthiness (not None, not empty, not False)
            if actual is None or actual is False or actual == "" or actual == {} or actual == []:
                return False
            return True

        if isinstance(expected, bool):
            return bool(actual) == expected

        if isinstance(expected, (int, float)):
            return actual == expected

        if isinstance(expected, str):
            clean_act = str(actual).strip().lower()
            clean_exp = expected.strip().lower()
            return clean_act == clean_exp or clean_exp in clean_act

        if isinstance(expected, dict):
            if not isinstance(actual, dict):
                return False
            for ek, ev in expected.items():
                if ek not in actual or not self._value_matches_expected(actual[ek], ev):
                    return False
            return True

        return actual == expected

    def _check_resource_regressions(self, change: ResourceChange) -> List[SemanticViolation]:
        """Detects security regressions introduced in modified resource attributes."""
        violations: List[SemanticViolation] = []
        before = change.before or {}
        after = change.after or {}

        # 1. Check known security attributes
        for attr, rule in self.security_attributes.items():
            b_found, b_val = resolve_nested_attribute(before, attr)
            a_found, a_val = resolve_nested_attribute(after, attr)

            # Check for silent drop of critical security attribute
            if rule.get("cannot_be_dropped") and b_found and b_val not in (None, False, "", {}, []):
                if not a_found or a_val in (None, "", {}, []):
                    violations.append(
                        SemanticViolation(
                            resource_address=change.address,
                            violation_type=SemanticViolationType.SECURITY_REGRESSION,
                            attribute_path=attr,
                            message=f"Security regression: {rule['description']}.",
                            expected=b_val,
                            actual=a_val,
                        )
                    )
                    continue

            # Check for transition into known insecure value
            insecure_vals = rule.get("insecure_values", [])
            if insecure_vals and a_found:
                # Was it secure before, but now insecure?
                was_secure = not b_found or b_val not in insecure_vals
                is_insecure = a_val in insecure_vals
                if was_secure and is_insecure:
                    violations.append(
                        SemanticViolation(
                            resource_address=change.address,
                            violation_type=SemanticViolationType.SECURITY_REGRESSION,
                            attribute_path=attr,
                            message=f"Security regression: {rule['description']}.",
                            expected=f"not in {insecure_vals}",
                            actual=a_val,
                        )
                    )

        # 2. Check TLS version downgrades (min_tls_version)
        b_tls_found, b_tls = resolve_nested_attribute(before, "min_tls_version")
        a_tls_found, a_tls = resolve_nested_attribute(after, "min_tls_version")
        if b_tls_found and a_tls_found and b_tls and a_tls:
            tls_ranks = {"tls1_0": 1, "tls1_1": 2, "tls1_2": 3, "tls1_3": 4}
            clean_b = str(b_tls).lower().replace(".", "_")
            clean_a = str(a_tls).lower().replace(".", "_")
            if clean_b in tls_ranks and clean_a in tls_ranks:
                if tls_ranks[clean_a] < tls_ranks[clean_b]:
                    violations.append(
                        SemanticViolation(
                            resource_address=change.address,
                            violation_type=SemanticViolationType.SECURITY_REGRESSION,
                            attribute_path="min_tls_version",
                            message=f"Security regression: TLS version downgraded from {b_tls} to {a_tls}.",
                            expected=b_tls,
                            actual=a_tls,
                        )
                    )

        # 3. Check S3 Versioning status downgrades
        b_v_found, b_v = resolve_nested_attribute(before, "versioning.enabled")
        a_v_found, a_v = resolve_nested_attribute(after, "versioning.enabled")
        if b_v_found and a_v_found and b_v is True and a_v is False:
            violations.append(
                SemanticViolation(
                    resource_address=change.address,
                    violation_type=SemanticViolationType.SECURITY_REGRESSION,
                    attribute_path="versioning.enabled",
                    message="Security regression: S3 bucket versioning was disabled.",
                    expected=True,
                    actual=False,
                )
            )

        b_vstat_found, b_vstat = resolve_nested_attribute(before, "versioning.status")
        a_vstat_found, a_vstat = resolve_nested_attribute(after, "versioning.status")
        if b_vstat_found and a_vstat_found:
            if str(b_vstat).lower() == "enabled" and str(a_vstat).lower() in ("suspended", "disabled"):
                violations.append(
                    SemanticViolation(
                        resource_address=change.address,
                        violation_type=SemanticViolationType.SECURITY_REGRESSION,
                        attribute_path="versioning.status",
                        message=f"Security regression: S3 bucket versioning status downgraded from {b_vstat} to {a_vstat}.",
                        expected="Enabled",
                        actual=a_vstat,
                    )
                )

        return violations

    def verify_remediation_task(
        self,
        changes: List[ResourceChange],
        task: RemediationTask,
    ) -> SemanticVerificationResult:
        """
        Synthesizes semantic requirements directly from a RemediationTask and verifies
        that the planned changes satisfy the task action without introducing regressions.
        """
        requirements: List[SemanticRequirement] = []
        action = task.action
        target_res = task.violation.resource_id

        if action and action.target_attribute:
            expected_val = None
            # If attribute_value provides a single-line attribute assignment, extract expected value;
            # if it is a block declaration (contains '{' or newlines), check presence/truthiness of block
            if action.attribute_value:
                attr_val_str = action.attribute_value.strip()
                if "\n" not in attr_val_str and "{" not in attr_val_str and " = " in attr_val_str:
                    _, rhs = attr_val_str.split(" = ", 1)
                    rhs_clean = rhs.strip().strip('"').strip("'")
                    if rhs_clean.lower() == "true":
                        expected_val = True
                    elif rhs_clean.lower() == "false":
                        expected_val = False
                    else:
                        expected_val = rhs_clean

            req = SemanticRequirement(
                resource_address=target_res,
                resource_type=task.violation.resource_type,
                attribute_path=action.target_attribute,
                expected_value=expected_val,
                allow_additive_attachment=(action.strategy == RemediationStrategy.ADDITIVE_ATTACHMENT),
                description=f"Satisfy {task.violation.check_id}: {action.description}",
                statute_reference=action.statute_reference,
            )
            requirements.append(req)

        return self.verify(changes=changes, requirements=requirements)
