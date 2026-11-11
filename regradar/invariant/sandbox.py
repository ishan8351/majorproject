import json
import os
import re
import shutil
import subprocess
import tempfile
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
from pydantic import BaseModel, Field

from regradar.invariant.invariant_engine import InvariantEngine
from regradar.invariant.models import InvariantReport
from regradar.invariant.plan_parser import PlanParser
from regradar.invariant.provider_mocks import (
    AWS_MOCK_HCL,
    detect_required_providers,
    get_provider_env_vars,
    write_mock_override_file,
)


class SandboxErrorCategory(str, Enum):
    """Classification of errors encountered during sandbox execution."""
    SYNTAX_ERROR = "SYNTAX_ERROR"
    PROVIDER_PLUGIN_MISSING = "PROVIDER_PLUGIN_MISSING"
    BINARY_NOT_FOUND = "BINARY_NOT_FOUND"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    EXECUTION_ERROR = "EXECUTION_ERROR"


class SandboxDiagnostic(BaseModel):
    """Detailed error diagnostics captured from tofu execution."""
    stage: str  # "init", "validate", "plan", "show"
    category: SandboxErrorCategory
    summary: str
    raw_output: str
    returncode: int = 1
    missing_providers: List[str] = Field(default_factory=list)
    syntax_details: List[str] = Field(default_factory=list)

    @property
    def is_syntax_error(self) -> bool:
        return self.category == SandboxErrorCategory.SYNTAX_ERROR

    @property
    def is_provider_missing(self) -> bool:
        return self.category == SandboxErrorCategory.PROVIDER_PLUGIN_MISSING

    @property
    def is_binary_missing(self) -> bool:
        return self.category == SandboxErrorCategory.BINARY_NOT_FOUND


class SandboxExecutionError(RuntimeError):
    """Exception raised when sandbox execution fails, containing detailed diagnostics."""
    def __init__(self, message: str, diagnostic: Optional[SandboxDiagnostic] = None):
        super().__init__(message)
        self.diagnostic = diagnostic

    @property
    def is_syntax_error(self) -> bool:
        return bool(self.diagnostic and self.diagnostic.is_syntax_error)

    @property
    def is_provider_missing(self) -> bool:
        return bool(self.diagnostic and self.diagnostic.is_provider_missing)

    @property
    def is_binary_missing(self) -> bool:
        return bool(self.diagnostic and self.diagnostic.is_binary_missing)


def diagnose_failure(
    stage: str, returncode: int, stdout: str, stderr: str
) -> SandboxDiagnostic:
    """
    Analyzes execution stdout/stderr to separate syntax errors, provider missing errors,
    and missing binaries.
    """
    combined = f"{stderr}\n{stdout}".strip()
    missing_providers: List[str] = []
    syntax_details: List[str] = []

    # 1. Binary not found check
    if returncode == 127 or "not found" in combined.lower() and ("binary" in combined.lower() or "command not found" in combined.lower()):
        return SandboxDiagnostic(
            stage=stage,
            category=SandboxErrorCategory.BINARY_NOT_FOUND,
            summary=f"OpenTofu/Terraform binary not found during '{stage}' stage",
            raw_output=combined,
            returncode=returncode,
        )

    # 2. Provider Plugin Missing checks
    provider_patterns = [
        re.compile(r'Failed to query available provider packages', re.IGNORECASE),
        re.compile(r'Could not retrieve provider\s+["\']?([^"\'\s\n]+)["\']?', re.IGNORECASE),
        re.compile(r'Failed to install provider', re.IGNORECASE),
        re.compile(r'no provider codebase found', re.IGNORECASE),
        re.compile(r'registry\.(?:opentofu|terraform)\.org/[^/\s]+/([a-zA-Z0-9_-]+)', re.IGNORECASE),
        re.compile(r'provider\s+["\']?([a-zA-Z0-9_-]+)["\']?\s+is not available', re.IGNORECASE),
        re.compile(r'Plugin reinitialization required', re.IGNORECASE),
        re.compile(r'cannot download provider', re.IGNORECASE),
    ]

    is_provider_missing = any(pat.search(combined) for pat in provider_patterns)
    if is_provider_missing:
        # Extract specific provider names if possible
        name_patterns = [
            re.compile(r'provider\s+["\']?([a-zA-Z0-9_-]+)["\']?', re.IGNORECASE),
            re.compile(r'registry\.(?:opentofu|terraform)\.org/[^/\s]+/([a-zA-Z0-9_-]+)', re.IGNORECASE),
            re.compile(r'hashicorp/([a-zA-Z0-9_-]+)', re.IGNORECASE),
        ]
        for pat in name_patterns:
            for match in pat.finditer(combined):
                pname = match.group(1).lower()
                if pname not in missing_providers and pname not in ("available", "plugin", "version"):
                    missing_providers.append(pname)

        summary = (
            f"Provider plugin(s) missing or could not be retrieved: {', '.join(missing_providers)}"
            if missing_providers
            else "Provider plugins could not be resolved or downloaded."
        )
        return SandboxDiagnostic(
            stage=stage,
            category=SandboxErrorCategory.PROVIDER_PLUGIN_MISSING,
            summary=summary,
            raw_output=combined,
            returncode=returncode,
            missing_providers=missing_providers,
        )

    # 3. Syntax Error checks
    syntax_patterns = [
        re.compile(r'Error:\s*(Argument or block definition required|Missing newline|Unsupported block type|Unsupported argument|Missing attribute value|Reference to undeclared|Invalid expression|Unclosed configuration block)', re.IGNORECASE),
        re.compile(r'syntax error', re.IGNORECASE),
        re.compile(r'HCL parse error', re.IGNORECASE),
        re.compile(r'Parsing\s+.*failed', re.IGNORECASE),
        re.compile(r'Error:\s*Missing required argument', re.IGNORECASE),
    ]

    is_syntax = any(pat.search(combined) for pat in syntax_patterns)
    if is_syntax:
        # Extract specific error lines
        for line in combined.splitlines():
            line_str = line.strip()
            if line_str.startswith("Error:") or "syntax" in line_str.lower() or "line " in line_str.lower():
                syntax_details.append(line_str)

        summary = (
            f"HCL syntax error detected: {syntax_details[0]}"
            if syntax_details
            else "HCL syntax or block definition error detected."
        )
        return SandboxDiagnostic(
            stage=stage,
            category=SandboxErrorCategory.SYNTAX_ERROR,
            summary=summary,
            raw_output=combined,
            returncode=returncode,
            syntax_details=syntax_details,
        )

    # 4. Configuration Error checks (e.g. cycle, duplicate)
    if "cycle:" in combined.lower() or "duplicate" in combined.lower():
        return SandboxDiagnostic(
            stage=stage,
            category=SandboxErrorCategory.CONFIGURATION_ERROR,
            summary=f"IaC configuration error detected during '{stage}'",
            raw_output=combined,
            returncode=returncode,
        )

    # 5. Default generic execution error
    first_line = combined.splitlines()[0] if combined else f"Stage '{stage}' failed with returncode {returncode}"
    return SandboxDiagnostic(
        stage=stage,
        category=SandboxErrorCategory.EXECUTION_ERROR,
        summary=first_line,
        raw_output=combined,
        returncode=returncode,
    )


def resolve_plugin_cache_dir(custom_cache_dir: Optional[str] = None) -> Optional[str]:
    """
    Resolves a writable plugin cache directory with graceful fallback.
    Tries ~/.terraform.d/plugin-cache first; falls back to a temporary directory
    if the home directory is read-only or inaccessible.
    """
    candidates: List[Path] = []
    if custom_cache_dir:
        candidates.append(Path(custom_cache_dir).expanduser())

    # Environment variable override if present
    env_cache = os.environ.get("TF_PLUGIN_CACHE_DIR")
    if env_cache:
        candidates.append(Path(env_cache).expanduser())

    # Standard default cache directory
    candidates.append(Path(os.path.expanduser("~/.terraform.d/plugin-cache")))

    # Ephemeral fallback in /tmp
    candidates.append(Path(tempfile.gettempdir()) / "regradar_plugin_cache")

    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            test_file = candidate / ".regradar_write_test"
            test_file.touch()
            test_file.unlink()
            return str(candidate)
        except (OSError, PermissionError):
            continue

    return None


class SandboxRunner:
    """
    Manages isolated pre-flight execution sandboxes using OpenTofu/Terraform CLI.
    Simulates proposed configuration changes against ephemeral state engines to inspect
    plan diffs before any mutation touches version control or cloud environments.

    Supports multi-cloud provider mocking (AWS, Azure, GCP, Kubernetes) and robust
    plugin cache fallback for read-only or restricted environments.
    """

    MOCK_PROVIDER_HCL = AWS_MOCK_HCL

    def __init__(
        self,
        binary_name: Optional[str] = None,
        plugin_cache_dir: Optional[str] = None,
        providers: Optional[Iterable[str]] = None,
    ):
        from regradar.config import get_config
        cfg = get_config().sandbox
        self.binary_name = binary_name or os.environ.get("REGRADAR_SANDBOX_BINARY") or cfg.binary_name
        self.custom_plugin_cache_dir = plugin_cache_dir or os.environ.get("TF_PLUGIN_CACHE_DIR") or cfg.plugin_cache_dir
        self.explicit_providers = list(providers) if providers else None
        self.last_diagnostic: Optional[SandboxDiagnostic] = None

    def run_command(
        self,
        cmd: list,
        cwd: Path,
        extra_env: Optional[Dict[str, str]] = None,
        active_providers: Optional[Iterable[str]] = None,
    ) -> Tuple[int, str, str]:
        """Runs an isolated sub-process with mocked cloud environment variables and plugin cache."""
        env = os.environ.copy()
        env["TF_IN_AUTOMATION"] = "1"

        # Resolve plugin cache directory with fallback
        cache_dir = resolve_plugin_cache_dir(self.custom_plugin_cache_dir)
        if cache_dir:
            env["TF_PLUGIN_CACHE_DIR"] = cache_dir

        # Multi-cloud mock credentials
        providers_to_mock = active_providers or self.explicit_providers or ["aws", "azurerm", "google", "kubernetes"]
        mock_env = get_provider_env_vars(providers_to_mock)
        env.update(mock_env)

        if extra_env:
            env.update(extra_env)

        try:
            result = subprocess.run(
                cmd,
                cwd=str(cwd),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return result.returncode, result.stdout, result.stderr
        except FileNotFoundError as e:
            return 127, "", f"Binary '{cmd[0]}' not found: {e}"
        except Exception as e:
            return 1, "", f"Subprocess execution error: {e}"

    def initialize_sandbox(
        self,
        sandbox_dir: Path,
        providers: Optional[Iterable[str]] = None,
    ) -> Tuple[bool, str]:
        """Runs tofu init in the sandbox directory with multi-cloud mock provider overrides."""
        target_providers = providers or self.explicit_providers
        override_file = sandbox_dir / "_regradar_mock_override.tf"
        if not override_file.exists():
            write_mock_override_file(
                directory=sandbox_dir,
                providers=target_providers,
                filename="_regradar_mock_override.tf",
            )

        detected = target_providers or detect_required_providers(directory=sandbox_dir)

        code, stdout, stderr = self.run_command(
            [self.binary_name, "init", "-backend=false", "-no-color"],
            cwd=sandbox_dir,
            active_providers=detected,
        )

        if code != 0:
            diag = diagnose_failure("init", code, stdout, stderr)
            self.last_diagnostic = diag
            return False, f"Initialization failed [{diag.category.value}]:\n{stderr or stdout}"

        return True, stdout

    def validate_sandbox(
        self,
        sandbox_dir: Path,
        providers: Optional[Iterable[str]] = None,
    ) -> Tuple[bool, str]:
        """Runs tofu validate in the sandbox."""
        detected = providers or self.explicit_providers or detect_required_providers(directory=sandbox_dir)
        code, stdout, stderr = self.run_command(
            [self.binary_name, "validate", "-no-color"],
            cwd=sandbox_dir,
            active_providers=detected,
        )
        if code != 0:
            diag = diagnose_failure("validate", code, stdout, stderr)
            self.last_diagnostic = diag
            return False, f"Validation failed [{diag.category.value}]:\n{stderr or stdout}"
        return True, stdout

    def generate_plan_json(
        self,
        sandbox_dir: Path,
        providers: Optional[Iterable[str]] = None,
    ) -> Tuple[bool, Optional[Dict], str]:
        """Generates an execution plan and extracts the JSON representation."""
        plan_binary = sandbox_dir / "regradar_plan.tfplan"
        detected = providers or self.explicit_providers or detect_required_providers(directory=sandbox_dir)

        code, stdout, stderr = self.run_command(
            [self.binary_name, "plan", f"-out={plan_binary.name}", "-no-color"],
            cwd=sandbox_dir,
            active_providers=detected,
        )
        if code != 0:
            diag = diagnose_failure("plan", code, stdout, stderr)
            self.last_diagnostic = diag
            return False, None, f"Plan generation failed [{diag.category.value}]:\n{stderr or stdout}"

        # Show JSON
        code, stdout, stderr = self.run_command(
            [self.binary_name, "show", "-json", plan_binary.name],
            cwd=sandbox_dir,
            active_providers=detected,
        )
        if code != 0:
            diag = diagnose_failure("show", code, stdout, stderr)
            self.last_diagnostic = diag
            return False, None, f"Failed to extract plan JSON [{diag.category.value}]:\n{stderr or stdout}"

        try:
            plan_data = json.loads(stdout)
            return True, plan_data, ""
        except json.JSONDecodeError as e:
            return False, None, f"Failed to parse plan JSON output: {e}"

    def simulate_and_verify(
        self,
        base_dir: Union[str, Path],
        modified_files: Optional[Dict[str, str]] = None,
        existing_plan_json: Optional[Dict] = None,
        providers: Optional[Iterable[str]] = None,
    ) -> InvariantReport:
        """
        Clones base_dir into a temporary sandbox, applies modified_files, runs tofu plan,
        and executes deterministic invariant checks.
        """
        # If pre-computed plan JSON is provided (e.g. for offline testing)
        if existing_plan_json:
            changes = PlanParser.parse_json_dict(existing_plan_json)
            engine = InvariantEngine()
            return engine.verify(changes)

        base_path = Path(base_dir).resolve()

        # If OpenTofu/Terraform binary is not available on host, fall back to offline AST invariant verification
        if shutil.which(self.binary_name) is None and shutil.which("tofu") is None and shutil.which("terraform") is None:
            return self._offline_ast_simulate_and_verify(
                base_dir=base_path,
                modified_files=modified_files,
            )

        with tempfile.TemporaryDirectory(prefix="regradar_sandbox_") as tmp_str:
            sandbox_path = Path(tmp_str)

            # Copy all files from base_path to sandbox_path
            for item in base_path.glob("*"):
                if item.name.startswith(".terraform") or item.name == ".git":
                    continue
                if item.is_dir():
                    shutil.copytree(item, sandbox_path / item.name)
                else:
                    shutil.copy2(item, sandbox_path / item.name)

            # Apply proposed file patches if any
            if modified_files:
                for rel_path, content in modified_files.items():
                    target_file = sandbox_path / rel_path
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    target_file.write_text(content, encoding="utf-8")

            # Determine providers
            target_providers = providers or self.explicit_providers

            # Execute Sandbox Pipeline
            init_ok, init_msg = self.initialize_sandbox(sandbox_path, providers=target_providers)
            if not init_ok:
                raise SandboxExecutionError(init_msg, diagnostic=self.last_diagnostic)

            val_ok, val_msg = self.validate_sandbox(sandbox_path, providers=target_providers)
            if not val_ok:
                raise SandboxExecutionError(val_msg, diagnostic=self.last_diagnostic)

            plan_ok, plan_data, plan_msg = self.generate_plan_json(sandbox_path, providers=target_providers)
            if not plan_ok:
                raise SandboxExecutionError(plan_msg, diagnostic=self.last_diagnostic)

            changes = PlanParser.parse_json_dict(plan_data)
            engine = InvariantEngine()
            return engine.verify(changes)

    def _offline_ast_simulate_and_verify(
        self,
        base_dir: Path,
        modified_files: Optional[Dict[str, str]] = None,
    ) -> InvariantReport:
        """
        Fallback deterministic AST invariant verification when OpenTofu binary is unavailable.
        Extracts resource additions, updates, and deletions from parsed HCL trees.
        """
        from regradar.parser.hcl_parser import HCLParser
        from regradar.invariant.models import ResourceChange

        parser = HCLParser()
        orig_resources: Dict[str, Any] = {}
        try:
            res_list = (
                parser.parse_directory(base_dir)
                if base_dir.is_dir()
                else parser.parse_file(base_dir)
            )
            orig_resources = res_list if isinstance(res_list, dict) else {r.id: r for r in res_list}
        except Exception:
            orig_resources = {}

        mod_resources: Dict[str, Any] = {}
        with tempfile.TemporaryDirectory(prefix="regradar_ast_sandbox_") as tmp_str:
            tmp_path = Path(tmp_str)
            if base_dir.is_dir():
                for item in base_dir.glob("*.tf"):
                    shutil.copy2(item, tmp_path / item.name)
            elif base_dir.is_file():
                shutil.copy2(base_dir, tmp_path / base_dir.name)

            if modified_files:
                for rel_path, content in modified_files.items():
                    target = tmp_path / rel_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(content, encoding="utf-8")

            try:
                res_list = parser.parse_directory(tmp_path)
                mod_resources = res_list if isinstance(res_list, dict) else {r.id: r for r in res_list}
            except Exception:
                mod_resources = {}

        changes: List[ResourceChange] = []
        for rid, res in mod_resources.items():
            if rid not in orig_resources:
                changes.append(
                    ResourceChange(
                        address=rid,
                        resource_type=res.resource_type,
                        name=res.name,
                        actions=["create"],
                        before=None,
                        after=res.attributes,
                    )
                )
            else:
                orig_res = orig_resources[rid]
                from regradar.config import get_config
                replacement_rules = get_config().sandbox.offline_replacement_rules
                is_replacement = False
                if res.resource_type in replacement_rules:
                    for attr_name in replacement_rules[res.resource_type]:
                        if res.attributes.get(attr_name) != orig_res.attributes.get(attr_name):
                            is_replacement = True
                            break

                if is_replacement:
                    changes.append(
                        ResourceChange(
                            address=rid,
                            resource_type=res.resource_type,
                            name=res.name,
                            actions=["delete", "create"],
                            before=orig_res.attributes,
                            after=res.attributes,
                        )
                    )
                elif res.attributes != orig_res.attributes:
                    changes.append(
                        ResourceChange(
                            address=rid,
                            resource_type=res.resource_type,
                            name=res.name,
                            actions=["update"],
                            before=orig_res.attributes,
                            after=res.attributes,
                        )
                    )

        for rid, res in orig_resources.items():
            if rid not in mod_resources:
                changes.append(
                    ResourceChange(
                        address=rid,
                        resource_type=res.resource_type,
                        name=res.name,
                        actions=["delete"],
                        before=res.attributes,
                        after=None,
                    )
                )

        engine = InvariantEngine(allow_additive_creations=True)
        return engine.verify(changes)
