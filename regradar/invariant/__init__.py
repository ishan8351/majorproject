"""
Sandboxed Dry-Run Invariant Enforcement Engine for RegRadar.
"""

from regradar.invariant.models import (
    PlanAction,
    ResourceChange,
    ViolationType,
    InvariantViolation,
    InvariantReport,
)
from regradar.invariant.plan_parser import PlanParser
from regradar.invariant.invariant_engine import InvariantEngine
from regradar.invariant.provider_mocks import (
    detect_required_providers,
    generate_mock_override_content,
    get_mock_provider_hcl,
    get_provider_env_vars,
    write_mock_override_file,
)
from regradar.invariant.sandbox import (
    SandboxDiagnostic,
    SandboxErrorCategory,
    SandboxExecutionError,
    SandboxRunner,
    diagnose_failure,
    resolve_plugin_cache_dir,
)
from regradar.invariant.semantic_verifier import (
    SemanticInvariantVerifier,
    SemanticRequirement,
    SemanticVerificationResult,
    SemanticViolation,
    SemanticViolationType,
)

__all__ = [
    "PlanAction",
    "ResourceChange",
    "ViolationType",
    "InvariantViolation",
    "InvariantReport",
    "PlanParser",
    "InvariantEngine",
    "SandboxRunner",
    "SandboxDiagnostic",
    "SandboxErrorCategory",
    "SandboxExecutionError",
    "diagnose_failure",
    "resolve_plugin_cache_dir",
    "detect_required_providers",
    "generate_mock_override_content",
    "get_mock_provider_hcl",
    "get_provider_env_vars",
    "write_mock_override_file",
    "SemanticInvariantVerifier",
    "SemanticRequirement",
    "SemanticVerificationResult",
    "SemanticViolation",
    "SemanticViolationType",
]
