import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Union

from regradar.remediation.models import ComplianceViolation


class CheckovScanner:
    """
    Integrates with Checkov CLI to perform static compliance audits and extract
    declarative IaC violations.
    """

    def __init__(self, checkov_path: Optional[str] = None):
        if checkov_path:
            self.checkov_bin = checkov_path
        else:
            # Check venv first, then system PATH
            venv_bin = Path(sys.prefix) / "bin" / "checkov"
            self.checkov_bin = str(venv_bin) if venv_bin.exists() else "checkov"

    def scan_directory(self, target_dir: Union[str, Path]) -> List[ComplianceViolation]:
        """Runs Checkov on the target directory and returns parsed violations."""
        path = Path(target_dir).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Directory not found: {path}")

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

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

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
