import pytest
from fastapi import HTTPException
from regradar.api.models import (
    ScanRequest,
    AuditRequest,
    ReviewStagedRequest,
    ReviewDecisionRequest,
    RemediationRequest,
    SandboxVerifyRequest,
    BenchmarkRunRequest,
)
from regradar.api.routes import (
    _resolve_target_path,
    scan_topology,
    export_graph,
    audit_compliance,
    get_staged_review,
    submit_review_decision,
    run_remediation,
    verify_sandbox,
    run_benchmark_endpoint,
)


def test_models_accept_none_target_path():
    """Ensures Pydantic models allow null/none target_path without 422 schema crashes."""
    assert ScanRequest().target_path is None
    assert ScanRequest(target_path=None).target_path is None
    assert AuditRequest(target_path=None).target_path is None
    assert ReviewStagedRequest(target_path=None).target_path is None
    assert ReviewDecisionRequest(resource_id="res.1", check_id="CKV_1", decision="APPROVE", target_path=None).target_path is None
    assert RemediationRequest(target_path=None).target_path is None
    assert SandboxVerifyRequest(target_path=None).target_path is None
    assert BenchmarkRunRequest(target_path=None).target_path is None


@pytest.mark.parametrize("invalid_path", [None, "", "   ", "null", "undefined", "none", "None", "NULL"])
def test_resolve_target_path_raises_400_for_empty_or_null(invalid_path):
    """Ensures empty, null, or undefined target_path raises clean HTTP 400."""
    with pytest.raises(HTTPException) as exc_info:
        _resolve_target_path(invalid_path)
    assert exc_info.value.status_code == 400
    assert "No remote repository specified" in exc_info.value.detail


def test_endpoints_failsafe_with_none():
    """Ensures each endpoint raises HTTP 400 with clean message when target_path is None."""
    endpoints_and_calls = [
        (scan_topology, ScanRequest(target_path=None)),
        (audit_compliance, AuditRequest(target_path=None)),
        (get_staged_review, ReviewStagedRequest(target_path=None)),
        (submit_review_decision, ReviewDecisionRequest(resource_id="r1", check_id="c1", decision="APPROVE", target_path=None)),
        (run_remediation, RemediationRequest(target_path=None)),
        (verify_sandbox, SandboxVerifyRequest(target_path=None)),
        (run_benchmark_endpoint, BenchmarkRunRequest(target_path=None)),
    ]

    for fn, req in endpoints_and_calls:
        with pytest.raises(HTTPException) as exc_info:
            fn(req)
        assert exc_info.value.status_code == 400
        assert "No remote repository specified" in exc_info.value.detail

    # Test export_graph
    with pytest.raises(HTTPException) as exc_info:
        export_graph(target_path=None, export_format="cytoscape")
    assert exc_info.value.status_code == 400
    assert "No remote repository specified" in exc_info.value.detail
