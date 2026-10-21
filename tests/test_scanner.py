import pytest

from regradar.remediation.scanner import CheckovScanner


def test_scanner_parse_report_dict():
    mock_data = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_19",
                    "check_name": "Ensure all data stored in the S3 bucket is secure_at_rest",
                    "resource": "aws_s3_bucket.audit_logs",
                    "file_path": "/main.tf",
                    "file_line_range": [40, 50],
                    "guideline": "https://docs.prismacloud.io",
                },
                {
                    "check_id": "CKV_AWS_79",
                    "check_name": "Ensure Instance Metadata Service Version 1 is not enabled",
                    "resource": "aws_instance.app_server",
                    "file_path": "/main.tf",
                    "file_line_range": [60, 70],
                },
            ]
        }
    }

    violations = CheckovScanner.parse_report_dict(mock_data)
    assert len(violations) == 2

    v1 = violations[0]
    assert v1.check_id == "CKV_AWS_19"
    assert v1.resource_id == "aws_s3_bucket.audit_logs"
    assert v1.resource_type == "aws_s3_bucket"
    assert any("HIPAA" in f for f in v1.frameworks)
    assert any("GDPR" in f for f in v1.frameworks)

    v2 = violations[1]
    assert v2.check_id == "CKV_AWS_79"
    assert any("NIST" in f for f in v2.frameworks)
