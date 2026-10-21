import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

from regradar.invariant.invariant_engine import InvariantEngine
from regradar.invariant.models import InvariantReport
from regradar.invariant.plan_parser import PlanParser


class SandboxRunner:
    """
    Manages isolated pre-flight execution sandboxes using OpenTofu/Terraform CLI.
    Simulates proposed configuration changes against ephemeral state engines to inspect
    plan diffs before any mutation touches version control or cloud environments.
    """

    MOCK_PROVIDER_HCL = """
provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  access_key                  = "mock_key"
  secret_key                  = "mock_secret"
}
"""

    def __init__(self, binary_name: str = "tofu"):
        self.binary_name = binary_name

    def run_command(
        self, cmd: list, cwd: Path, extra_env: Optional[Dict[str, str]] = None
    ) -> Tuple[int, str, str]:
        """Runs an isolated sub-process with mocked cloud environment variables."""
        cache_dir = os.path.expanduser("~/.terraform.d/plugin-cache")
        os.makedirs(cache_dir, exist_ok=True)

        env = os.environ.copy()
        env["AWS_ACCESS_KEY_ID"] = "mock_key"
        env["AWS_SECRET_ACCESS_KEY"] = "mock_secret"
        env["AWS_DEFAULT_REGION"] = "us-east-1"
        env["TF_IN_AUTOMATION"] = "1"
        env["TF_PLUGIN_CACHE_DIR"] = cache_dir
        if extra_env:
            env.update(extra_env)

        result = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.returncode, result.stdout, result.stderr

    def initialize_sandbox(self, sandbox_dir: Path) -> Tuple[bool, str]:
        """Runs tofu init in the sandbox directory."""
        # Inject mock provider helper if no provider is present
        override_file = sandbox_dir / "_regradar_mock_override.tf"
        if not override_file.exists():
            override_file.write_text(self.MOCK_PROVIDER_HCL, encoding="utf-8")

        code, stdout, stderr = self.run_command(
            [self.binary_name, "init", "-backend=false", "-no-color"],
            cwd=sandbox_dir,
        )
        if code != 0:
            return False, f"Initialization failed:\n{stderr or stdout}"
        return True, stdout

    def validate_sandbox(self, sandbox_dir: Path) -> Tuple[bool, str]:
        """Runs tofu validate in the sandbox."""
        code, stdout, stderr = self.run_command(
            [self.binary_name, "validate", "-no-color"],
            cwd=sandbox_dir,
        )
        if code != 0:
            return False, f"Validation failed:\n{stderr or stdout}"
        return True, stdout

    def generate_plan_json(self, sandbox_dir: Path) -> Tuple[bool, Optional[Dict], str]:
        """Generates an execution plan and extracts the JSON representation."""
        plan_binary = sandbox_dir / "regradar_plan.tfplan"

        code, stdout, stderr = self.run_command(
            [self.binary_name, "plan", f"-out={plan_binary.name}", "-no-color"],
            cwd=sandbox_dir,
        )
        if code != 0:
            return False, None, f"Plan generation failed:\n{stderr or stdout}"

        # Show JSON
        code, stdout, stderr = self.run_command(
            [self.binary_name, "show", "-json", plan_binary.name],
            cwd=sandbox_dir,
        )
        if code != 0:
            return False, None, f"Failed to extract plan JSON:\n{stderr or stdout}"

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

            # Execute Sandbox Pipeline
            init_ok, init_msg = self.initialize_sandbox(sandbox_path)
            if not init_ok:
                raise RuntimeError(init_msg)

            val_ok, val_msg = self.validate_sandbox(sandbox_path)
            if not val_ok:
                raise RuntimeError(val_msg)

            plan_ok, plan_data, plan_msg = self.generate_plan_json(sandbox_path)
            if not plan_ok:
                raise RuntimeError(plan_msg)

            changes = PlanParser.parse_json_dict(plan_data)
            engine = InvariantEngine()
            return engine.verify(changes)
