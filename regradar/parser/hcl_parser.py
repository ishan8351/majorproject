import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
import hcl2

from regradar.models import TerraformResource
from regradar.parser.reference_extractor import ReferenceExtractor
from regradar.parser.module_resolver import ModuleResolver, sanitize_identifier


def extract_module_prefix(resource_id: str) -> str:
    """
    Extracts the module prefix from a hierarchical resource ID.
    e.g. 'module.vpc.aws_subnet.public' -> 'module.vpc'
         'module.a.module.b.aws_instance.vm' -> 'module.a.module.b'
         'aws_vpc.main' -> ''
    """
    parts = resource_id.split(".")
    i = 0
    prefix_parts = []
    while i < len(parts) and parts[i] == "module":
        if i + 1 < len(parts):
            prefix_parts.extend([parts[i], parts[i + 1]])
            i += 2
        else:
            break
    return ".".join(prefix_parts)


class HCLParser:
    """
    Parses Terraform HCL files into normalized AST and extracts resource declarations.
    Supports multi-cloud providers (AWS, Azure, GCP, Kubernetes), data sources,
    and recursive local child module resolution.
    """

    SUPPORTED_PROVIDERS = {"aws", "azurerm", "google", "kubernetes"}

    def __init__(self):
        self.resources: Dict[str, TerraformResource] = {}
        self.module_resolver = ModuleResolver()

    @staticmethod
    def detect_provider(resource_type: str) -> str:
        """
        Detects the cloud or infrastructure provider for a given resource type.
        Supports AWS (aws_*), Azure (azurerm_*), GCP (google_*), and Kubernetes (kubernetes_*).
        """
        clean = resource_type.removeprefix("data.")
        for prefix in ("aws", "azurerm", "google", "kubernetes"):
            if clean.startswith(f"{prefix}_"):
                return prefix
        return clean.split("_")[0] if "_" in clean else "unknown"

    def parse_file(self, file_path: Union[str, Path]) -> Dict[str, TerraformResource]:
        """Parses a single .tf file and returns discovered resources and data sources."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            try:
                parsed_data = hcl2.load(f)
            except Exception as e:
                raise ValueError(f"HCL parse error in {path.name}: {e}") from e

        all_resources = self._extract_resources(parsed_data, str(path))

        # Module resolution for single file
        module_outputs: Dict[str, Set[str]] = {}
        module_inputs: Dict[str, Dict[str, Set[str]]] = {}
        module_to_resources: Dict[str, Set[str]] = {}

        raw_modules = parsed_data.get("module", [])
        for mod_block in raw_modules:
            for mod_name, mod_conf in mod_block.items():
                clean_mod_name = sanitize_identifier(mod_name)
                src = mod_conf.get("source", "")
                resolved = self.module_resolver.resolve_local_module(
                    source=src,
                    caller_dir=path.parent,
                    module_name=clean_mod_name,
                    input_args=mod_conf,
                )
                if resolved:
                    child_res = resolved.get_all_resources()
                    all_resources.update(child_res)
                    module_outputs.update(resolved.get_all_output_mappings())
                    module_inputs.update(resolved.get_all_input_dependencies())
                    module_to_resources[f"module.{clean_mod_name}"] = set(child_res.keys())

        # Resolve cross references
        self._cross_link_references(all_resources, module_outputs, module_inputs, module_to_resources)
        self.resources = all_resources
        return all_resources

    def parse_directory(self, dir_path: Union[str, Path], recursive: bool = False) -> Dict[str, TerraformResource]:
        """
        Parses all .tf files in a directory, extracts resources and data sources,
        resolves child modules recursively, and cross-links references between all entities.
        """
        directory = Path(dir_path).resolve()
        if not directory.is_dir():
            raise NotADirectoryError(f"Directory not found: {directory}")

        pattern = "**/*.tf" if recursive else "*.tf"
        tf_files = [
            f for f in directory.glob(pattern)
            if not any(part.startswith(".") for part in f.relative_to(directory).parts)  # ignore .terraform, etc.
        ]

        # Phase 1: Ingest all resources, data sources, and modules from all files
        all_resources: Dict[str, TerraformResource] = {}
        module_outputs: Dict[str, Set[str]] = {}
        module_inputs: Dict[str, Dict[str, Set[str]]] = {}
        module_to_resources: Dict[str, Set[str]] = {}

        for tf_file in tf_files:
            try:
                with open(tf_file, "r", encoding="utf-8") as f:
                    parsed_data = hcl2.load(f)
            except Exception as e:
                raise ValueError(f"HCL parse error in {tf_file.name}: {e}") from e

            # Extract managed resources and data sources
            file_res = self._extract_resources(parsed_data, str(tf_file))
            all_resources.update(file_res)

            # Discover and resolve module blocks
            raw_modules = parsed_data.get("module", [])
            for mod_block in raw_modules:
                for mod_name, mod_conf in mod_block.items():
                    clean_mod_name = sanitize_identifier(mod_name)
                    src = mod_conf.get("source", "")
                    resolved = self.module_resolver.resolve_local_module(
                        source=src,
                        caller_dir=tf_file.parent,
                        module_name=clean_mod_name,
                        input_args=mod_conf,
                    )
                    if resolved:
                        child_res = resolved.get_all_resources()
                        all_resources.update(child_res)
                        module_outputs.update(resolved.get_all_output_mappings())
                        module_inputs.update(resolved.get_all_input_dependencies())
                        module_to_resources[f"module.{clean_mod_name}"] = set(child_res.keys())

        # Phase 2: Resolve references against all discovered resources
        self._cross_link_references(all_resources, module_outputs, module_inputs, module_to_resources)
        self.resources = all_resources
        return all_resources

    def _cross_link_references(
        self,
        all_resources: Dict[str, TerraformResource],
        module_outputs: Dict[str, Set[str]],
        module_inputs: Dict[str, Dict[str, Set[str]]],
        module_to_resources: Dict[str, Set[str]],
    ) -> None:
        """Resolves implicit and explicit dependencies across all resources, modules, and data sources."""
        known_ids = set(all_resources.keys())

        for res_id, res in all_resources.items():
            mod_prefix = extract_module_prefix(res_id)

            # 1. Inferred references from attributes
            raw_refs = ReferenceExtractor.extract_from_value(res.attributes)
            valid_refs: Set[str] = set()

            for r in raw_refs:
                if r in known_ids and r != res_id:
                    valid_refs.add(r)
                elif r in module_outputs:
                    for target in module_outputs[r]:
                        if target in known_ids and target != res_id:
                            valid_refs.add(target)
                elif r in module_to_resources:
                    for mod_res in module_to_resources[r]:
                        if mod_res != res_id:
                            valid_refs.add(mod_res)

            # Scoped resolution for child module resources
            if mod_prefix:
                for r in raw_refs:
                    scoped_r = f"{mod_prefix}.{r}"
                    if scoped_r in known_ids and scoped_r != res_id:
                        valid_refs.add(scoped_r)
                    elif scoped_r in module_outputs:
                        for target in module_outputs[scoped_r]:
                            if target in known_ids and target != res_id:
                                valid_refs.add(target)

                # Inherit input dependencies passed to this module
                var_refs = ReferenceExtractor.extract_variables(res.attributes)
                mod_deps = module_inputs.get(mod_prefix, {})
                for vr in var_refs:
                    if vr in mod_deps:
                        for idep in mod_deps[vr]:
                            if idep in known_ids and idep != res_id:
                                valid_refs.add(idep)
                            elif idep in module_outputs:
                                for target in module_outputs[idep]:
                                    if target in known_ids and target != res_id:
                                        valid_refs.add(target)

            res.inferred_dependencies = valid_refs

            # 2. Explicit dependencies (depends_on)
            valid_explicit: Set[str] = set()
            for dep in res.explicit_dependencies:
                if dep in known_ids and dep != res_id:
                    valid_explicit.add(dep)
                elif dep in module_outputs:
                    for target in module_outputs[dep]:
                        if target in known_ids and target != res_id:
                            valid_explicit.add(target)
                elif dep in module_to_resources:
                    for mod_res in module_to_resources[dep]:
                        if mod_res != res_id:
                            valid_explicit.add(mod_res)
                elif mod_prefix and f"{mod_prefix}.{dep}" in known_ids:
                    valid_explicit.add(f"{mod_prefix}.{dep}")

            res.explicit_dependencies = valid_explicit

    def _extract_resources(self, parsed: dict, file_path: str) -> Dict[str, TerraformResource]:
        """Extracts managed resources and data sources from a parsed HCL dictionary."""
        extracted: Dict[str, TerraformResource] = {}

        # 1. Managed Resources (AWS, Azure, GCP, Kubernetes, etc.)
        raw_resources = parsed.get("resource", [])
        for res_block in raw_resources:
            for res_type, instances in res_block.items():
                clean_type = sanitize_identifier(res_type)
                for instance_name, config in instances.items():
                    clean_name = sanitize_identifier(instance_name)
                    res_id = f"{clean_type}.{clean_name}"
                    explicit_deps = ReferenceExtractor.extract_explicit_depends_on(config)

                    res = TerraformResource(
                        id=res_id,
                        resource_type=clean_type,
                        name=clean_name,
                        file_path=file_path,
                        attributes=config,
                        explicit_dependencies=explicit_deps,
                        inferred_dependencies=set(),
                    )
                    extracted[res_id] = res

        # 2. Data Sources (e.g., data "aws_ami" "ubuntu" -> node ID data.aws_ami.ubuntu)
        raw_data = parsed.get("data", [])
        for data_block in raw_data:
            for data_type, instances in data_block.items():
                clean_type = sanitize_identifier(data_type)
                for instance_name, config in instances.items():
                    clean_name = sanitize_identifier(instance_name)
                    data_id = f"data.{clean_type}.{clean_name}"
                    explicit_deps = ReferenceExtractor.extract_explicit_depends_on(config)

                    res = TerraformResource(
                        id=data_id,
                        resource_type=f"data.{clean_type}",
                        name=clean_name,
                        file_path=file_path,
                        attributes=config,
                        explicit_dependencies=explicit_deps,
                        inferred_dependencies=set(),
                    )
                    extracted[data_id] = res

        return extracted
