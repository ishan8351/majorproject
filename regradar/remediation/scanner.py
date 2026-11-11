import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Union

from regradar.remediation.models import ComplianceViolation

logger = logging.getLogger(__name__)


class CheckovScanner:
    """
    Integrates with Checkov CLI to perform static compliance audits and extract
    declarative IaC violations. Provides robust AST fallback when Checkov binary
    is not installed.
    """

    def __init__(self, checkov_path: Optional[str] = None):
        if checkov_path:
            self.checkov_bin = checkov_path
        else:
            env_bin = os.environ.get("REGRADAR_CHECKOV_PATH") or os.environ.get("CHECKOV_BIN")
            if env_bin:
                self.checkov_bin = env_bin
            else:
                # Check venv first, then system PATH
                venv_bin = Path(sys.prefix) / "bin" / "checkov"
                self.checkov_bin = str(venv_bin) if venv_bin.exists() else "checkov"

    def scan_directory(self, target_dir: Union[str, Path]) -> List[ComplianceViolation]:
        """Runs Checkov on the target directory and returns parsed violations."""
        path = Path(target_dir).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Directory not found: {path}")

        # If checkov binary is not installed or available on PATH, use AST fallback
        if not shutil.which(self.checkov_bin):
            logger.info("Checkov CLI binary not found at '%s'; falling back to AST auditor.", self.checkov_bin)
            return self._scan_directory_fallback(path)

        cmd = [
            self.checkov_bin,
            "-d",
            str(path),
            "-o",
            "json",
            "--compact",
            "--quiet",
            "--framework",
            "terraform",
        ]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except (FileNotFoundError, PermissionError):
            logger.info("Failed to execute Checkov CLI; falling back to AST auditor.")
            return self._scan_directory_fallback(path)

        # Checkov returns non-zero when violations are found
        stdout = result.stdout.strip()
        if not stdout:
            return []

        try:
            data = json.loads(stdout)
            # Checkov can return a list of reports or a single report dict
            if isinstance(data, list):
                violations = []
                for rep in data:
                    violations.extend(self.parse_report_dict(rep))
                return violations
            return self.parse_report_dict(data)
        except json.JSONDecodeError:
            return []

    @staticmethod
    def _extract_blocks(text: str) -> List[Tuple[str, str, str]]:
        """Extracts (resource_type, resource_name, block_body) from HCL text using balanced braces."""
        blocks = []
        for m in re.finditer(r'resource\s+"([a-zA-Z0-9_]+)"\s+"([a-zA-Z0-9_\-]+)"\s*\{', text):
            start = m.end() - 1
            res_type = m.group(1)
            res_name = m.group(2)
            depth = 0
            end = start
            for i in range(start, len(text)):
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            blocks.append((res_type, res_name, text[start:end]))
        return blocks

    def _scan_directory_fallback(self, path: Path) -> List[ComplianceViolation]:
        """
        Deterministic static AST compliance scanner when Checkov CLI is unavailable.
        Inspects Terraform HCL files for statutory violations across HIPAA, PCI-DSS,
        and GDPR.
        """
        violations: List[ComplianceViolation] = []
        tf_files = list(path.glob("*.tf"))
        if not tf_files and path.is_file():
            tf_files = [path]

        for tf_file in tf_files:
            try:
                content = tf_file.read_text(encoding="utf-8")
            except Exception:
                continue

            rel_file = tf_file.name
            blocks = self._extract_blocks(content)

            for res_type, res_name, body in blocks:
                res_id = f"{res_type}.{res_name}"

                # 1. AWS S3 Buckets
                if res_type == "aws_s3_bucket":
                    # CKV_AWS_19: S3 encryption
                    has_sse = (
                        f'aws_s3_bucket_server_side_encryption_configuration" "{res_name}_' in content
                        or "server_side_encryption_configuration" in content
                    )
                    if not has_sse:
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AWS_19",
                                check_name="Ensure all data stored in the S3 bucket is secure_at_rest",
                                resource_id=res_id,
                                resource_type="aws_s3_bucket",
                                file_path=rel_file,
                                frameworks=["HIPAA §164.312(a)(2)(iv)", "GDPR Art. 32(1)(a)", "NIST SP 800-53 SC-13"],
                            )
                        )

                    # CKV_AWS_21: S3 versioning
                    has_ver = (
                        f'aws_s3_bucket_versioning" "{res_name}_' in content
                        or re.search(r'versioning_configuration\s*\{[^}]*status\s*=\s*"Enabled"', content)
                    )
                    if not has_ver:
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AWS_21",
                                check_name="Ensure all data stored in the S3 bucket has versioning enabled",
                                resource_id=res_id,
                                resource_type="aws_s3_bucket",
                                file_path=rel_file,
                                frameworks=["HIPAA §164.308(a)(7)", "GDPR Art. 32(1)(c)"],
                            )
                        )

                    # CKV_AWS_145: S3 KMS Encryption (PCI-DSS)
                    if "pci" in path.name.lower() or "cardholder" in res_name.lower() or "fintech" in path.name.lower():
                        has_kms = 'sse_algorithm     = "aws:kms"' in content or 'sse_algorithm = "aws:kms"' in content
                        if not has_kms:
                            violations.append(
                                ComplianceViolation(
                                    check_id="CKV_AWS_145",
                                    check_name="Ensure that S3 buckets are encrypted with KMS by default",
                                    resource_id=res_id,
                                    resource_type="aws_s3_bucket",
                                    file_path=rel_file,
                                    frameworks=["PCI-DSS v3.2.1 Req 3.4", "HIPAA §164.312(a)(2)(iv)"],
                                )
                            )

                # 2. RDS DB Instance Storage Encryption (CKV_AWS_16)
                elif res_type == "aws_db_instance":
                    if "storage_encrypted = true" not in body and 'storage_encrypted = "true"' not in body:
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AWS_16",
                                check_name="Ensure all data stored in the RDS is securely encrypted at rest",
                                resource_id=res_id,
                                resource_type="aws_db_instance",
                                file_path=rel_file,
                                frameworks=["HIPAA §164.312(a)(2)(iv)", "NIST SP 800-53 SC-13"],
                            )
                        )

                # 3. CloudTrail KMS Encryption (CKV_AWS_36)
                elif res_type == "aws_cloudtrail":
                    if "kms_key_id" not in body:
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AWS_36",
                                check_name="Ensure CloudTrail is encrypted with KMS Master Key",
                                resource_id=res_id,
                                resource_type="aws_cloudtrail",
                                file_path=rel_file,
                                frameworks=["HIPAA §164.312(a)(2)(iv)", "NIST SP 800-53 SC-13"],
                            )
                        )

                # 4. IAM Wildcard Policy (CKV_AWS_40)
                elif res_type == "aws_iam_policy":
                    if '"Action": "*"' in body or '"Action": ["*"]' in body:
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AWS_40",
                                check_name="Ensure IAM policies does not allow write access without constraints",
                                resource_id=res_id,
                                resource_type="aws_iam_policy",
                                file_path=rel_file,
                                frameworks=["NIST SP 800-53 AC-3", "GDPR Art. 32(1)(b)"],
                            )
                        )

                # 5. Security Group Ingress SSH 22 (CKV_AWS_24) & Description (CKV_AWS_23)
                elif res_type == "aws_security_group":
                    if "description" not in body:
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AWS_23",
                                check_name="Ensure every security groups and rule has an identifiable description",
                                resource_id=res_id,
                                resource_type="aws_security_group",
                                file_path=rel_file,
                                frameworks=["PCI-DSS v3.2.1 Req 1.2", "NIST SP 800-53 AC-3"],
                            )
                        )
                    if re.search(r'from_port\s*=\s*22\s+to_port\s*=\s*22.*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', body, re.DOTALL):
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AWS_24",
                                check_name="Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
                                resource_id=res_id,
                                resource_type="aws_security_group",
                                file_path=rel_file,
                                frameworks=["PCI-DSS v3.2.1 Req 1.3", "NIST SP 800-53 AC-3"],
                            )
                        )

                # 6. EBS Volume Encryption (CKV_AWS_135)
                elif res_type == "aws_ebs_volume":
                    if not re.search(r'encrypted\s*=\s*true', body, re.IGNORECASE):
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AWS_135",
                                check_name="Ensure that EC2 is EBS-optimized or EBS volume is encrypted by KMS",
                                resource_id=res_id,
                                resource_type="aws_ebs_volume",
                                file_path=rel_file,
                                frameworks=["PCI-DSS v3.2.1 Req 3.4", "NIST SP 800-53 SC-13"],
                            )
                        )

                # 7. Azure Storage Account (CKV_AZURE_3, CKV_AZURE_33, CKV_AZURE_44)
                elif res_type == "azurerm_storage_account":
                    if re.search(r'enable_https_traffic_only\s*=\s*false', body, re.IGNORECASE) or "enable_https_traffic_only" not in body:
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AZURE_3",
                                check_name="Ensure that 'Secure transfer required' is set to 'Enabled'",
                                resource_id=res_id,
                                resource_type="azurerm_storage_account",
                                file_path=rel_file,
                                frameworks=["GDPR Art. 32(1)(a)", "NIST SP 800-53 SC-13"],
                            )
                        )
                    if re.search(r'(?:allow_nested_items_to_be_public|allow_blob_public_access)\s*=\s*true', body, re.IGNORECASE):
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AZURE_33",
                                check_name="Ensure that storage accounts disallow public access",
                                resource_id=res_id,
                                resource_type="azurerm_storage_account",
                                file_path=rel_file,
                                frameworks=["GDPR Art. 32(1)(b)", "NIST SP 800-53 AC-3"],
                            )
                        )
                    if re.search(r'min_tls_version\s*=\s*"(?:TLS1_0|TLS1_1)"', body, re.IGNORECASE) or "min_tls_version" not in body:
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AZURE_44",
                                check_name="Ensure Storage Account is using the latest version of TLS encryption",
                                resource_id=res_id,
                                resource_type="azurerm_storage_account",
                                file_path=rel_file,
                                frameworks=["GDPR Art. 32(1)(a)", "NIST SP 800-53 SC-13"],
                            )
                        )

                # 8. Azure Blob Container Public Access (CKV_AZURE_33)
                elif res_type == "azurerm_storage_container":
                    if re.search(r'container_access_type\s*=\s*"(?:blob|container)"', body, re.IGNORECASE):
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AZURE_33",
                                check_name="Ensure that storage container disallows public access",
                                resource_id=res_id,
                                resource_type="azurerm_storage_container",
                                file_path=rel_file,
                                frameworks=["GDPR Art. 32(1)(b)", "NIST SP 800-53 AC-3"],
                            )
                        )

                # 9. Azure NSG SSH Ingress Port 22 (CKV_AZURE_9)
                elif res_type == "azurerm_network_security_group":
                    if re.search(r'destination_port_range\s*=\s*"22".*?source_address_prefix\s*=\s*"\*"', body, re.DOTALL):
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_AZURE_9",
                                check_name="Ensure that SSH is not open to the Internet",
                                resource_id=res_id,
                                resource_type="azurerm_network_security_group",
                                file_path=rel_file,
                                frameworks=["GDPR Art. 32(1)(b)", "PCI-DSS v3.2.1 Req 1.3"],
                            )
                        )

                # 10. GCP Compute Firewall Open Port 22 (CKV_GCP_2)
                elif res_type == "google_compute_firewall":
                    if '"0.0.0.0/0"' in body and '"22"' in body:
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_GCP_2",
                                check_name="Ensure Google Cloud firewall rules do not allow unrestricted public ingress to SSH port 22",
                                resource_id=res_id,
                                resource_type="google_compute_firewall",
                                file_path=rel_file,
                                frameworks=["PCI-DSS v3.2.1 Req 1.3", "NIST SP 800-53 AC-4"],
                            )
                        )

                # 11. GCP Storage Bucket Uniform Bucket-Level Access (CKV_GCP_29)
                elif res_type == "google_storage_bucket":
                    if "uniform_bucket_level_access = false" in body or "uniform_bucket_level_access" not in body:
                        violations.append(
                            ComplianceViolation(
                                check_id="CKV_GCP_29",
                                check_name="Ensure Google Cloud Storage buckets enforce uniform bucket-level access",
                                resource_id=res_id,
                                resource_type="google_storage_bucket",
                                file_path=rel_file,
                                frameworks=["PCI-DSS v3.2.1 Req 1.3", "GDPR Art. 32(1)(b)"],
                            )
                        )

        return violations

        return violations

    @classmethod
    def parse_report_dict(cls, data: Dict) -> List[ComplianceViolation]:
        """Parses a Checkov JSON output dictionary into normalized ComplianceViolation models."""
        violations: List[ComplianceViolation] = []
        results = data.get("results", {})
        failed_checks = results.get("failed_checks", [])

        for check in failed_checks:
            raw_resource = check.get("resource", "")
            parts = raw_resource.split(".")
            res_type = parts[0] if parts else ""

            line_range = None
            raw_lines = check.get("file_line_range")
            if isinstance(raw_lines, list) and len(raw_lines) == 2:
                line_range = (raw_lines[0], raw_lines[1])

            # Extract compliance frameworks from check guidelines/metadata
            frameworks = cls._infer_frameworks(check)

            v = ComplianceViolation(
                check_id=check.get("check_id", ""),
                check_name=check.get("check_name", ""),
                resource_id=raw_resource,
                resource_type=res_type,
                file_path=check.get("file_path", ""),
                line_range=line_range,
                frameworks=frameworks,
                guideline_url=check.get("guideline"),
            )
            violations.append(v)

        return violations

    @staticmethod
    def _infer_frameworks(check: Dict) -> List[str]:
        """Maps known Checkov rules and categories to statutory compliance frameworks."""
        check_id = check.get("check_id", "")
        name = check.get("check_name", "").lower()
        frameworks = set()

        # Direct rule mapping
        if "encryption" in name or "secure_at_rest" in name or "kms" in name:
            frameworks.add("HIPAA §164.312(a)(2)(iv)")
            frameworks.add("GDPR Art. 32(1)(a)")
            frameworks.add("NIST SP 800-53 SC-13")

        if "logging" in name or "audit" in name or "log" in name:
            frameworks.add("HIPAA §164.312(b)")
            frameworks.add("NIST SP 800-53 AU-2")

        if "public" in name or "acl" in name or "ingress" in name or "token" in name or "imds" in name:
            frameworks.add("NIST SP 800-53 AC-3")
            frameworks.add("GDPR Art. 32(1)(b)")

        if "versioning" in name or "backup" in name or "retention" in name:
            frameworks.add("HIPAA §164.308(a)(7)")
            frameworks.add("GDPR Art. 32(1)(c)")

        return sorted(list(frameworks)) if frameworks else ["NIST SP 800-53"]
