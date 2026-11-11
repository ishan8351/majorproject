"""
Multi-Cloud Provider Mocking for RegRadar Dry-Run Sandbox.

Generates mock provider configurations and overrides for AWS, Azure, Google Cloud,
and Kubernetes, enabling local OpenTofu/Terraform execution without live cloud credentials.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Union


# Canonical Provider Mock HCL Definitions
AWS_MOCK_HCL = """provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  access_key                  = "mock_key"
  secret_key                  = "mock_secret"
}"""

AZURE_MOCK_HCL = """provider "azurerm" {
  features {}
  skip_provider_registration = true
  subscription_id            = "00000000-0000-0000-0000-000000000000"
  client_id                  = "00000000-0000-0000-0000-000000000000"
  client_secret              = "mock_secret"
  tenant_id                  = "00000000-0000-0000-0000-000000000000"
}"""

GCP_MOCK_HCL = """provider "google" {
  project                     = "mock-project"
  skip_credentials_validation = true
  region                      = "us-central1"
  zone                        = "us-central1-a"
}"""

KUBERNETES_MOCK_HCL = """provider "kubernetes" {
  host                   = "http://localhost:8080"
  client_certificate     = "mock_cert"
  client_key             = "mock_key"
  cluster_ca_certificate = "mock_ca"
}"""

# Mapping canonical provider name to its HCL mock template
PROVIDER_HCL_TEMPLATES: Dict[str, str] = {
    "aws": AWS_MOCK_HCL,
    "azurerm": AZURE_MOCK_HCL,
    "google": GCP_MOCK_HCL,
    "kubernetes": KUBERNETES_MOCK_HCL,
}

# Provider name aliases
PROVIDER_ALIASES: Dict[str, str] = {
    "aws": "aws",
    "azure": "azurerm",
    "azurerm": "azurerm",
    "gcp": "google",
    "google": "google",
    "google-beta": "google",
    "k8s": "kubernetes",
    "kubernetes": "kubernetes",
}

# Mapping resource/data type prefixes to canonical provider name
RESOURCE_PREFIX_TO_PROVIDER: Dict[str, str] = {
    "aws": "aws",
    "azurerm": "azurerm",
    "azure": "azurerm",
    "google": "google",
    "kubernetes": "kubernetes",
}

# Mock environment variables for each cloud provider
PROVIDER_MOCK_ENV_VARS: Dict[str, Dict[str, str]] = {
    "aws": {
        "AWS_ACCESS_KEY_ID": "mock_key",
        "AWS_SECRET_ACCESS_KEY": "mock_secret",
        "AWS_DEFAULT_REGION": "us-east-1",
    },
    "azurerm": {
        "ARM_CLIENT_ID": "00000000-0000-0000-0000-000000000000",
        "ARM_CLIENT_SECRET": "mock_secret",
        "ARM_SUBSCRIPTION_ID": "00000000-0000-0000-0000-000000000000",
        "ARM_TENANT_ID": "00000000-0000-0000-0000-000000000000",
        "ARM_SKIP_PROVIDER_REGISTRATION": "true",
    },
    "google": {
        "GOOGLE_PROJECT": "mock-project",
        "GOOGLE_REGION": "us-central1",
        "GOOGLE_ZONE": "us-central1-a",
    },
    "kubernetes": {
        "KUBECONFIG": "/dev/null",
    },
}


def normalize_provider_name(provider: str) -> Optional[str]:
    """Normalizes an arbitrary provider string or alias to canonical provider name."""
    clean = provider.strip().lower().strip('"').strip("'")
    return PROVIDER_ALIASES.get(clean)


def get_mock_provider_hcl(provider: str) -> str:
    """Returns mock HCL block for a specific cloud provider, dynamically resolving environment variables."""
    canonical = normalize_provider_name(provider)
    if not canonical or canonical not in PROVIDER_HCL_TEMPLATES:
        raise ValueError(
            f"Unsupported provider '{provider}'. Supported: {sorted(PROVIDER_HCL_TEMPLATES.keys())}"
        )

    aws_region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"
    aws_key = os.environ.get("AWS_ACCESS_KEY_ID", "mock_key")
    aws_secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "mock_secret")

    azure_sub = os.environ.get("ARM_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000000")
    azure_client = os.environ.get("ARM_CLIENT_ID", "00000000-0000-0000-0000-000000000000")
    azure_secret = os.environ.get("ARM_CLIENT_SECRET", "mock_secret")
    azure_tenant = os.environ.get("ARM_TENANT_ID", "00000000-0000-0000-0000-000000000000")

    gcp_project = os.environ.get("GOOGLE_PROJECT") or os.environ.get("GCP_PROJECT") or "mock-project"
    gcp_region = os.environ.get("GOOGLE_REGION") or os.environ.get("GCP_REGION") or "us-central1"
    gcp_zone = os.environ.get("GOOGLE_ZONE") or os.environ.get("GCP_ZONE") or "us-central1-a"

    if canonical == "aws":
        return f"""provider "aws" {{
  region                      = "{aws_region}"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  access_key                  = "{aws_key}"
  secret_key                  = "{aws_secret}"
}}"""
    elif canonical == "azurerm":
        return f"""provider "azurerm" {{
  features {{}}
  skip_provider_registration = true
  subscription_id            = "{azure_sub}"
  client_id                  = "{azure_client}"
  client_secret              = "{azure_secret}"
  tenant_id                  = "{azure_tenant}"
}}"""
    elif canonical == "google":
        return f"""provider "google" {{
  project                     = "{gcp_project}"
  skip_credentials_validation = true
  region                      = "{gcp_region}"
  zone                        = "{gcp_zone}"
}}"""
    elif canonical == "kubernetes":
        return KUBERNETES_MOCK_HCL

    return PROVIDER_HCL_TEMPLATES[canonical]


def get_provider_env_vars(providers: Iterable[str]) -> Dict[str, str]:
    """Returns composite mock/live environment variables for the specified providers."""
    env_vars: Dict[str, str] = {}
    for prov in providers:
        canonical = normalize_provider_name(prov)
        if canonical == "aws":
            env_vars["AWS_ACCESS_KEY_ID"] = os.environ.get("AWS_ACCESS_KEY_ID", "mock_key")
            env_vars["AWS_SECRET_ACCESS_KEY"] = os.environ.get("AWS_SECRET_ACCESS_KEY", "mock_secret")
            env_vars["AWS_DEFAULT_REGION"] = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"
        elif canonical == "azurerm":
            env_vars["ARM_CLIENT_ID"] = os.environ.get("ARM_CLIENT_ID", "00000000-0000-0000-0000-000000000000")
            env_vars["ARM_CLIENT_SECRET"] = os.environ.get("ARM_CLIENT_SECRET", "mock_secret")
            env_vars["ARM_SUBSCRIPTION_ID"] = os.environ.get("ARM_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000000")
            env_vars["ARM_TENANT_ID"] = os.environ.get("ARM_TENANT_ID", "00000000-0000-0000-0000-000000000000")
            env_vars["ARM_SKIP_PROVIDER_REGISTRATION"] = "true"
        elif canonical == "google":
            env_vars["GOOGLE_PROJECT"] = os.environ.get("GOOGLE_PROJECT") or os.environ.get("GCP_PROJECT") or "mock-project"
            env_vars["GOOGLE_REGION"] = os.environ.get("GOOGLE_REGION") or os.environ.get("GCP_REGION") or "us-central1"
            env_vars["GOOGLE_ZONE"] = os.environ.get("GOOGLE_ZONE") or os.environ.get("GCP_ZONE") or "us-central1-a"
        elif canonical == "kubernetes":
            env_vars["KUBECONFIG"] = os.environ.get("KUBECONFIG", "/dev/null")
    return env_vars


def detect_required_providers(
    directory: Optional[Union[str, Path]] = None,
    files: Optional[Iterable[Union[str, Path]]] = None,
    resources: Optional[Iterable[Any]] = None,
    file_contents: Optional[Dict[str, str]] = None,
) -> Set[str]:
    """
    Detects which cloud providers are required by inspecting discovered resources,
    Terraform files in a directory, or provided in-memory file contents.

    Defaults to {'aws'} if no recognizable providers are found, preserving backward
    compatibility.
    """
    detected: Set[str] = set()

    # 1. Inspect explicit resource objects if provided (e.g. TerraformResource or dicts)
    if resources:
        for res in resources:
            res_type = getattr(res, "resource_type", None)
            if not res_type and isinstance(res, dict):
                res_type = res.get("resource_type") or res.get("type")
            if res_type:
                prefix = str(res_type).split("_")[0].lower()
                prov = RESOURCE_PREFIX_TO_PROVIDER.get(prefix)
                if prov:
                    detected.add(prov)

    # 2. Collect .tf files to scan
    tf_paths: List[Path] = []
    if files:
        for f in files:
            p = Path(f)
            if p.is_file() and p.suffix == ".tf":
                tf_paths.append(p)

    if directory:
        dir_path = Path(directory).resolve()
        if dir_path.is_dir():
            for p in dir_path.glob("*.tf"):
                if not p.name.startswith("_regradar"):
                    tf_paths.append(p)

    # Scan file contents from disk
    content_list: List[str] = []
    for tf_file in tf_paths:
        try:
            content_list.append(tf_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    # 3. Add in-memory file contents if provided
    if file_contents:
        for filename, content in file_contents.items():
            if not filename.startswith("_regradar"):
                content_list.append(content)

    # 4. Regex detection across all collected HCL content
    # Patterns for resources, data sources, provider blocks, and required_providers
    res_pattern = re.compile(r'(?:resource|data)\s+"([a-zA-Z0-9_-]+)"\s+"')
    prov_block_pattern = re.compile(r'provider\s+"([a-zA-Z0-9_-]+)"')
    req_prov_pattern = re.compile(r'([a-zA-Z0-9_-]+)\s*=\s*\{\s*source')

    for content in content_list:
        # Match resource / data types
        for match in res_pattern.finditer(content):
            rtype = match.group(1).lower()
            prefix = rtype.split("_")[0]
            prov = RESOURCE_PREFIX_TO_PROVIDER.get(prefix)
            if prov:
                detected.add(prov)

        # Match provider blocks
        for match in prov_block_pattern.finditer(content):
            pname = match.group(1).lower()
            canon = normalize_provider_name(pname)
            if canon:
                detected.add(canon)

        # Match required_providers
        for match in req_prov_pattern.finditer(content):
            pname = match.group(1).lower()
            canon = normalize_provider_name(pname)
            if canon:
                detected.add(canon)

    # Default fallback to AWS if nothing detected
    if not detected:
        detected.add("aws")

    return detected


def generate_mock_override_content(providers: Iterable[str]) -> str:
    """
    Generates composite _regradar_mock_override.tf HCL content containing mock
    provider configurations for all specified providers.
    """
    normalized_providers: List[str] = []
    for p in providers:
        canonical = normalize_provider_name(p)
        if canonical and canonical not in normalized_providers:
            normalized_providers.append(canonical)

    if not normalized_providers:
        normalized_providers = ["aws"]

    # Sort for deterministic output
    normalized_providers.sort()

    blocks = [
        "// Auto-generated by RegRadar Multi-Cloud Sandbox Engine",
        "// Ephemeral dry-run provider mocks for local plan simulation",
        "",
    ]
    for p in normalized_providers:
        blocks.append(f"# Mock provider configuration for {p}")
        blocks.append(get_mock_provider_hcl(p))
        blocks.append("")

    return "\n".join(blocks).strip() + "\n"


def write_mock_override_file(
    directory: Union[str, Path],
    providers: Optional[Iterable[str]] = None,
    filename: str = "_regradar_mock_override.tf",
) -> Path:
    """
    Writes composite mock provider override file into the target directory.
    If providers is None, automatically detects required providers.
    """
    target_dir = Path(directory).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    if providers is None:
        detected_providers = detect_required_providers(directory=target_dir)
    else:
        detected_providers = set(providers)

    override_content = generate_mock_override_content(detected_providers)
    override_path = target_dir / filename
    override_path.write_text(override_content, encoding="utf-8")
    return override_path
