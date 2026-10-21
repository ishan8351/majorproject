from typing import Dict, List, Optional

from regradar.remediation.models import RemediationAction, RemediationStrategy


class RegulatoryKnowledgeBase:
    """
    Ontological knowledge base mapping statutory regulatory mandates (HIPAA, GDPR, NIST)
    to verifiable IaC configuration requirements and non-destructive remediation strategies.
    """

    RULES: Dict[str, RemediationAction] = {
        # 1. HIPAA Encryption at Rest / GDPR Data Protection
        "CKV_AWS_19": RemediationAction(
            check_id="CKV_AWS_19",
            framework="HIPAA",
            statute_reference="HIPAA §164.312(a)(2)(iv) & GDPR Art. 32(1)(a)",
            strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
            additive_resource_template="""
resource "aws_s3_bucket_server_side_encryption_configuration" "{name}_encryption" {{
  bucket = {resource_id}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}
""",
            description="Enforce default AES-256 server-side encryption via additive attachment.",
        ),
        # 2. S3 Bucket Versioning (HIPAA Contingency Plan / Disaster Recovery)
        "CKV_AWS_21": RemediationAction(
            check_id="CKV_AWS_21",
            framework="HIPAA",
            statute_reference="HIPAA §164.308(a)(7)(ii)(A) & GDPR Art. 32(1)(c)",
            strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
            additive_resource_template="""
resource "aws_s3_bucket_versioning" "{name}_versioning" {{
  bucket = {resource_id}.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}
""",
            description="Enforce immutable object versioning for data recovery.",
        ),
        # 3. S3 Public Access Block (NIST Access Enforcement)
        "CKV_AWS_53": RemediationAction(
            check_id="CKV_AWS_53",
            framework="NIST SP 800-53",
            statute_reference="NIST SP 800-53 AC-3 / AC-4 & GDPR Art. 32",
            strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
            additive_resource_template="""
resource "aws_s3_bucket_public_access_block" "{name}_public_block" {{
  bucket = {resource_id}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
""",
            description="Enforce universal public access block on cloud storage.",
        ),
        # 4. EC2 IMDSv2 Enforcement (NIST Protection from Credential Theft)
        "CKV_AWS_79": RemediationAction(
            check_id="CKV_AWS_79",
            framework="NIST SP 800-53",
            statute_reference="NIST SP 800-53 SC-8 / IA-2",
            strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
            target_attribute="metadata_options",
            attribute_value="""  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }""",
            description="Mandate IMDSv2 token-based authentication to prevent SSRF credential theft.",
        ),
        # 5. EC2 EBS Optimization (Performance & Resilience)
        "CKV_AWS_135": RemediationAction(
            check_id="CKV_AWS_135",
            framework="NIST SP 800-53",
            statute_reference="NIST SP 800-53 CP-2 (Contingency Plan)",
            strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
            target_attribute="ebs_optimized",
            attribute_value="  ebs_optimized = true",
            description="Enable dedicated EBS throughput for persistent I/O integrity.",
        ),
        # 6. Security Group Descriptions (NIST Audit & Accountability)
        "CKV_AWS_23": RemediationAction(
            check_id="CKV_AWS_23",
            framework="NIST SP 800-53",
            statute_reference="NIST SP 800-53 AC-4 / AU-3",
            strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
            target_attribute="description",
            attribute_value='  description = "RegRadar managed: TLS ingress restricted to secure endpoints"',
            description="Enforce security policy audit descriptions on firewalls.",
        ),
    }

    @classmethod
    def get_action_for_check(cls, check_id: str) -> Optional[RemediationAction]:
        """Retrieves verified non-destructive remediation action for a check ID."""
        return cls.RULES.get(check_id)

    @classmethod
    def get_supported_checks(cls) -> List[str]:
        return list(cls.RULES.keys())
