import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
import hcl2

from regradar.models import TerraformResource
from regradar.parser.reference_extractor import ReferenceExtractor


def sanitize_identifier(val: Any) -> str:
    """Strips leading/trailing whitespace and quotes to ensure clean resource IDs."""
    if val is None:
        return ""
    s = str(val).strip()
    while len(s) >= 2 and ((s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'"))):
        s = s[1:-1].strip()
    return s


@dataclass
class ModuleOutput:
    """Represents an exported output block from a Terraform module."""
    name: str
    value: Any
    description: Optional[str] = None
    target_references: Set[str] = field(default_factory=set)


@dataclass
class ModuleVariable:
    """Represents an input variable declaration in a Terraform module."""
    name: str
    default: Any = None
    type: Optional[str] = None
    description: Optional[str] = None


@dataclass
class ResolvedModule:
    """
    Represents a fully resolved local Terraform child module, containing its resources,
    declared variables, exported outputs, and recursively resolved nested child modules.
    """
    name: str
    source: str
    module_path: Path
    prefix: str  # e.g., "module.vpc" or "module.root.module.child"
    inputs: Dict[str, Any] = field(default_factory=dict)
    input_dependencies: Dict[str, Set[str]] = field(default_factory=dict)
    variables: Dict[str, ModuleVariable] = field(default_factory=dict)
    outputs: Dict[str, ModuleOutput] = field(default_factory=dict)
    resources: Dict[str, TerraformResource] = field(default_factory=dict)
    child_modules: Dict[str, "ResolvedModule"] = field(default_factory=dict)

    def get_all_resources(self) -> Dict[str, TerraformResource]:
        """Returns all resources across this module and any nested child modules."""
        all_res: Dict[str, TerraformResource] = dict(self.resources)
        for child in self.child_modules.values():
            all_res.update(child.get_all_resources())
        return all_res

    def get_all_output_mappings(self) -> Dict[str, Set[str]]:
        """
        Returns mapping from fully qualified output references (e.g. 'module.vpc.subnet_id')
        to resolved downstream target resource IDs.
        """
        mappings: Dict[str, Set[str]] = {}
        for out_name, out_def in self.outputs.items():
            full_ref = f"{self.prefix}.{out_name}"
            mappings[full_ref] = set(out_def.target_references)
        for child in self.child_modules.values():
            mappings.update(child.get_all_output_mappings())
        return mappings

    def get_all_input_dependencies(self) -> Dict[str, Dict[str, Set[str]]]:
        """
        Returns mapping of module prefixes to their variable input dependencies.
        e.g., {'module.vpc': {'vpc_id': {'aws_vpc.main'}}}.
        """
        deps_map: Dict[str, Dict[str, Set[str]]] = {self.prefix: dict(self.input_dependencies)}
        for child in self.child_modules.values():
            deps_map.update(child.get_all_input_dependencies())
        return deps_map


class ModuleResolver:
    """
    Recursively discovers and resolves local child Terraform modules.
    Extracts module inputs, exported outputs, and hierarchical resource bindings.
    """

    META_ARGUMENTS = {
        "source",
        "version",
        "providers",
        "depends_on",
        "count",
        "for_each",
        "lifecycle",
        "__is_block__",
    }

    def resolve_local_module(
        self,
        source: str,
        caller_dir: Union[str, Path],
        module_name: str,
        input_args: Optional[Dict[str, Any]] = None,
        parent_prefix: str = "",
        visited_dirs: Optional[Set[Path]] = None,
    ) -> Optional[ResolvedModule]:
        """
        Resolves a local child Terraform module from disk recursively.

        Args:
            source: Source attribute specified in the module block (e.g. "./modules/vpc").
            caller_dir: Directory containing the calling Terraform file.
            module_name: Clean identifier of the module instance (e.g. "vpc").
            input_args: Input variables and arguments passed to the module call.
            parent_prefix: Hierarchical module prefix path (e.g. "module.parent").
            visited_dirs: Set of directory paths visited in the current resolution chain.

        Returns:
            ResolvedModule containing parsed resources and metadata, or None if external/invalid.
        """
        clean_source = sanitize_identifier(source)
        clean_name = sanitize_identifier(module_name)
        input_args = input_args or {}

        caller_path = Path(caller_dir).resolve()
        target_dir = (caller_path / clean_source).resolve()

        if not target_dir.is_dir():
            # Check relative to caller's parent or direct path
            alt_target = Path(clean_source).resolve()
            if alt_target.is_dir():
                target_dir = alt_target
            else:
                # External module (e.g. registry or git repo) or non-existent local directory
                return None

        # Cycle prevention in recursive module resolution
        current_visited = set(visited_dirs) if visited_dirs else set()
        if target_dir in current_visited:
            return None
        current_visited.add(target_dir)

        # Hierarchical prefix (e.g., "module.vpc" or "module.parent.module.child")
        prefix = f"{parent_prefix}.module.{clean_name}" if parent_prefix else f"module.{clean_name}"

        # Discover all .tf files in the module directory (skip hidden files)
        tf_files = [
            f for f in target_dir.glob("*.tf")
            if not any(part.startswith(".") for part in f.relative_to(target_dir).parts)
        ]

        # Extract explicit module-level depends_on from caller
        module_explicit_deps = ReferenceExtractor.extract_explicit_depends_on(input_args)

        # Ingest inputs passed to child module and their candidate dependencies
        inputs: Dict[str, Any] = {}
        input_dependencies: Dict[str, Set[str]] = {}
        for k, v in input_args.items():
            clean_k = sanitize_identifier(k)
            if clean_k in self.META_ARGUMENTS:
                continue
            inputs[clean_k] = v
            input_dependencies[clean_k] = ReferenceExtractor.extract_from_value(v)

        variables: Dict[str, ModuleVariable] = {}
        raw_outputs: List[Dict[str, Any]] = []
        raw_resources: List[Dict[str, Any]] = []
        raw_data_sources: List[Dict[str, Any]] = []
        raw_child_modules: List[Dict[str, Any]] = []

        # Parse all .tf files in module directory
        for tf_file in tf_files:
            try:
                with open(tf_file, "r", encoding="utf-8") as f:
                    parsed = hcl2.load(f)
            except Exception:
                continue

            # Variables
            for var_block in parsed.get("variable", []):
                for v_name, v_conf in var_block.items():
                    clean_v = sanitize_identifier(v_name)
                    if isinstance(v_conf, dict):
                        variables[clean_v] = ModuleVariable(
                            name=clean_v,
                            default=v_conf.get("default"),
                            type=str(v_conf.get("type")) if "type" in v_conf else None,
                            description=v_conf.get("description"),
                        )

            # Outputs
            for out_block in parsed.get("output", []):
                raw_outputs.append((out_block, str(tf_file)))

            # Resources
            for res_block in parsed.get("resource", []):
                raw_resources.append((res_block, str(tf_file)))

            # Data sources
            for data_block in parsed.get("data", []):
                raw_data_sources.append((data_block, str(tf_file)))

            # Child modules
            for mod_block in parsed.get("module", []):
                raw_child_modules.append((mod_block, str(tf_file)))

        resources: Dict[str, TerraformResource] = {}

        # 1. Instantiate child resources with hierarchical prefix
        for res_block, file_path in raw_resources:
            for res_type, instances in res_block.items():
                clean_type = sanitize_identifier(res_type)
                for instance_name, config in instances.items():
                    clean_res_name = sanitize_identifier(instance_name)
                    res_id = f"{prefix}.{clean_type}.{clean_res_name}"

                    explicit_deps = ReferenceExtractor.extract_explicit_depends_on(config)
                    # Inherit module-level explicit dependencies
                    explicit_deps.update(module_explicit_deps)

                    res = TerraformResource(
                        id=res_id,
                        resource_type=clean_type,
                        name=clean_res_name,
                        file_path=file_path,
                        attributes=config,
                        explicit_dependencies=explicit_deps,
                        inferred_dependencies=set(),
                    )
                    resources[res_id] = res

        # 2. Instantiate child data sources with hierarchical prefix
        for data_block, file_path in raw_data_sources:
            for data_type, instances in data_block.items():
                clean_type = sanitize_identifier(data_type)
                for instance_name, config in instances.items():
                    clean_data_name = sanitize_identifier(instance_name)
                    data_id = f"{prefix}.data.{clean_type}.{clean_data_name}"

                    explicit_deps = ReferenceExtractor.extract_explicit_depends_on(config)
                    explicit_deps.update(module_explicit_deps)

                    res = TerraformResource(
                        id=data_id,
                        resource_type=f"data.{clean_type}",
                        name=clean_data_name,
                        file_path=file_path,
                        attributes=config,
                        explicit_dependencies=explicit_deps,
                        inferred_dependencies=set(),
                    )
                    resources[data_id] = res

        # 3. Resolve child modules recursively
        child_modules: Dict[str, ResolvedModule] = {}
        for mod_block, file_path in raw_child_modules:
            for child_name, child_conf in mod_block.items():
                clean_child_name = sanitize_identifier(child_name)
                child_src = child_conf.get("source", "")
                resolved_child = self.resolve_local_module(
                    source=child_src,
                    caller_dir=target_dir,
                    module_name=clean_child_name,
                    input_args=child_conf,
                    parent_prefix=prefix,
                    visited_dirs=current_visited,
                )
                if resolved_child:
                    child_modules[clean_child_name] = resolved_child

        # 4. Resolve exported outputs
        outputs: Dict[str, ModuleOutput] = {}
        for out_block, _ in raw_outputs:
            for out_name, out_conf in out_block.items():
                clean_out_name = sanitize_identifier(out_name)
                if not isinstance(out_conf, dict):
                    continue
                out_val = out_conf.get("value")
                out_desc = out_conf.get("description")

                # Extract raw references inside the output expression
                raw_refs = ReferenceExtractor.extract_from_value(out_val)
                target_refs: Set[str] = set()

                for r in raw_refs:
                    # In child module scope, map local references to hierarchical IDs
                    if r.startswith("module."):
                        target_refs.add(f"{prefix}.{r}")
                    elif r.startswith("data."):
                        target_refs.add(f"{prefix}.{r}")
                    else:
                        # Local resource: aws_subnet.public -> module.vpc.aws_subnet.public
                        target_refs.add(f"{prefix}.{r}")

                # Check if output references a variable directly
                var_refs = ReferenceExtractor.extract_variables(out_val)
                for vr in var_refs:
                    if vr in input_dependencies:
                        target_refs.update(input_dependencies[vr])

                outputs[clean_out_name] = ModuleOutput(
                    name=clean_out_name,
                    value=out_val,
                    description=out_desc,
                    target_references=target_refs,
                )

        return ResolvedModule(
            name=clean_name,
            source=clean_source,
            module_path=target_dir,
            prefix=prefix,
            inputs=inputs,
            input_dependencies=input_dependencies,
            variables=variables,
            outputs=outputs,
            resources=resources,
            child_modules=child_modules,
        )
