import json
from pathlib import Path
import pytest

from regradar.cli import main as cli_main, review_directory
from regradar.models import CentralityMetrics, GraphSummary, RiskTier
from regradar.remediation.models import ComplianceViolation


@pytest.fixture
def mock_tf_environment(tmp_path):
    tf_file = tmp_path / "main.tf"
    tf_content = (
        'resource "aws_vpc" "prod_vpc" {\n'
        '  cidr_block = "10.0.0.0/16"\n'
        '}\n\n'
        'resource "aws_s3_bucket" "audit_bucket" {\n'
        '  bucket = "prod-audit-data"\n'
        '}\n'
    )
    tf_file.write_text(tf_content, encoding="utf-8")

    metrics = {
        "aws_vpc.prod_vpc": CentralityMetrics(
            node_id="aws_vpc.prod_vpc",
            resource_type="aws_vpc",
            in_degree=0,
            out_degree=2,
            descendant_count=4,
            ancestor_count=0,
            betweenness=0.5,
            blast_radius_score=0.75,
            risk_tier=RiskTier.CRITICAL_ROOT,
            auto_remediate=False,
        ),
        "aws_s3_bucket.audit_bucket": CentralityMetrics(
            node_id="aws_s3_bucket.audit_bucket",
            resource_type="aws_s3_bucket",
            in_degree=0,
            out_degree=0,
            descendant_count=0,
            ancestor_count=0,
            betweenness=0.0,
            blast_radius_score=0.05,
            risk_tier=RiskTier.LEAF_SAFE,
            auto_remediate=True,
        ),
    }

    summary = GraphSummary(
        total_resources=2,
        total_dependencies=1,
        root_resources=["aws_vpc.prod_vpc"],
        leaf_resources=["aws_s3_bucket.audit_bucket"],
        metrics=metrics,
    )

    violations = [
        ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="Ensure S3 bucket has server side encryption",
            resource_id="aws_s3_bucket.audit_bucket",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        ComplianceViolation(
            check_id="CKV_AWS_119",
            check_name="Ensure VPC flow logging is enabled",
            resource_id="aws_vpc.prod_vpc",
            resource_type="aws_vpc",
            file_path="main.tf",
        ),
    ]

    return {
        "dir": tmp_path,
        "file": tf_file,
        "initial_content": tf_content,
        "summary": summary,
        "violations": violations,
    }


def test_cli_review_dry_run_mode(mock_tf_environment):
    env = mock_tf_environment

    # User enters "a" (Approve), but apply_changes=False (dry-run)
    inputs = iter(["a"])
    exit_code = review_directory(
        target_dir=str(env["dir"]),
        apply_changes=False,
        non_interactive=False,
        input_func=lambda _: next(inputs),
        precomputed_violations=env["violations"],
        precomputed_summary=env["summary"],
    )

    assert exit_code == 0
    # Dry-run: disk file content should NOT have changed
    assert env["file"].read_text(encoding="utf-8") == env["initial_content"]


def test_cli_review_apply_mode(mock_tf_environment):
    env = mock_tf_environment

    # Operator approves both human item and apply_changes=True
    inputs = iter(["a"])
    exit_code = review_directory(
        target_dir=str(env["dir"]),
        apply_changes=True,
        non_interactive=False,
        input_func=lambda _: next(inputs),
        precomputed_violations=env["violations"],
        precomputed_summary=env["summary"],
    )

    assert exit_code == 0
    # File content should have been modified
    new_content = env["file"].read_text(encoding="utf-8")
    assert new_content != env["initial_content"]
    assert "aws_s3_bucket_server_side_encryption_configuration" in new_content


def test_cli_review_non_interactive_mode(mock_tf_environment, tmp_path):
    env = mock_tf_environment
    json_path = tmp_path / "decisions.json"

    # In non-interactive mode, input_func should NOT be called at all
    def unexpected_input(prompt):
        pytest.fail(f"input_func should not be called in non-interactive mode: {prompt}")

    exit_code = review_directory(
        target_dir=str(env["dir"]),
        apply_changes=False,
        non_interactive=True,
        export_json=str(json_path),
        input_func=unexpected_input,
        precomputed_violations=env["violations"],
        precomputed_summary=env["summary"],
    )

    assert exit_code == 0
    assert json_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["non_interactive"] is True
    assert data["autonomous_approved"] >= 1
    assert data["human_skipped"] >= 1

    # Check human task decision was marked SKIPPED
    human_dec = next(d for d in data["decisions"] if d["resource_id"] == "aws_vpc.prod_vpc")
    assert human_dec["decision"] == "SKIPPED"


def test_cli_review_interactive_reject(mock_tf_environment, tmp_path):
    env = mock_tf_environment
    json_path = tmp_path / "decisions.json"

    inputs = iter(["r"])
    exit_code = review_directory(
        target_dir=str(env["dir"]),
        apply_changes=False,
        non_interactive=False,
        export_json=str(json_path),
        input_func=lambda _: next(inputs),
        precomputed_violations=env["violations"],
        precomputed_summary=env["summary"],
    )

    assert exit_code == 0
    data = json.loads(json_path.read_text(encoding="utf-8"))
    human_dec = next(d for d in data["decisions"] if d["resource_id"] == "aws_vpc.prod_vpc")
    assert human_dec["decision"] == "REJECTED"
    assert data["human_rejected"] == 1


def test_cli_review_interactive_skip(mock_tf_environment, tmp_path):
    env = mock_tf_environment
    json_path = tmp_path / "decisions.json"

    inputs = iter(["s"])
    exit_code = review_directory(
        target_dir=str(env["dir"]),
        apply_changes=False,
        non_interactive=False,
        export_json=str(json_path),
        input_func=lambda _: next(inputs),
        precomputed_violations=env["violations"],
        precomputed_summary=env["summary"],
    )

    assert exit_code == 0
    data = json.loads(json_path.read_text(encoding="utf-8"))
    human_dec = next(d for d in data["decisions"] if d["resource_id"] == "aws_vpc.prod_vpc")
    assert human_dec["decision"] == "SKIPPED"
    assert data["human_skipped"] == 1


def test_cli_review_interactive_quit(mock_tf_environment, tmp_path):
    env = mock_tf_environment
    json_path = tmp_path / "decisions.json"

    inputs = iter(["q"])
    exit_code = review_directory(
        target_dir=str(env["dir"]),
        apply_changes=False,
        non_interactive=False,
        export_json=str(json_path),
        input_func=lambda _: next(inputs),
        precomputed_violations=env["violations"],
        precomputed_summary=env["summary"],
    )

    assert exit_code == 0
    data = json.loads(json_path.read_text(encoding="utf-8"))
    human_dec = next(d for d in data["decisions"] if d["resource_id"] == "aws_vpc.prod_vpc")
    assert human_dec["decision"] == "QUIT"


def test_cli_review_no_violations(tmp_path):
    clean_tf = tmp_path / "main.tf"
    clean_tf.write_text('resource "aws_vpc" "clean" { cidr_block = "10.0.0.0/16" }\n', encoding="utf-8")
    json_path = tmp_path / "decisions.json"

    exit_code = review_directory(
        target_dir=str(tmp_path),
        export_json=str(json_path),
        precomputed_violations=[],
    )

    assert exit_code == 0
    assert json_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["total_violations"] == 0


def test_cli_review_subcommand_dispatch(tmp_path, monkeypatch):
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "aws_vpc" "v" { cidr_block = "10.0.0.0/16" }\n', encoding="utf-8")
    json_file = tmp_path / "out.json"

    test_args = [
        "cli.py",
        "review",
        str(tmp_path),
        "--non-interactive",
        "--json", str(json_file),
    ]
    monkeypatch.setattr("sys.argv", test_args)

    with pytest.raises(SystemExit) as exc_info:
        cli_main()

    assert exc_info.value.code == 0
    assert json_file.exists()


def test_cli_review_short_flag_non_interactive(tmp_path, monkeypatch):
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "aws_vpc" "v" { cidr_block = "10.0.0.0/16" }\n', encoding="utf-8")

    test_args = [
        "cli.py",
        "review",
        str(tmp_path),
        "-y",
    ]
    monkeypatch.setattr("sys.argv", test_args)

    with pytest.raises(SystemExit) as exc_info:
        cli_main()

    assert exc_info.value.code == 0
