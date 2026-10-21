import os
from pathlib import Path
from typing import Dict, List, Union
import hcl2

from regradar.models import TerraformResource
from regradar.parser.reference_extractor import ReferenceExtractor


class HCLParser:
    """
    Parses Terraform HCL files into normalized AST and extracts resource declarations.
    """

    def __init__(self):
        self.resources: Dict[str, TerraformResource] = {}

    def parse_file(self, file_path: Union[str, Path]) -> Dict[str, TerraformResource]:
        """Parses a single .tf file and returns discovered resources."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            try:
                parsed_data = hcl2.load(f)
            except Exception as e:
                raise ValueError(f"HCL parse error in {path.name}: {e}") from e

        return self._extract_resources(parsed_data, str(path))

    def parse_directory(self, dir_path: Union[str, Path], recursive: bool = False) -> Dict[str, TerraformResource]:
        """
        Parses all .tf files in a directory, extracts resources,
        and cross-links references between all files.
        """
        directory = Path(dir_path).resolve()
        if not directory.is_dir():
            raise NotADirectoryError(f"Directory not found: {directory}")

        pattern = "**/*.tf" if recursive else "*.tf"
        tf_files = [
            f for f in directory.glob(pattern)
            if not any(part.startswith(".") for part in f.parts)  # ignore .terraform, etc.
        ]

        # Phase 1: Ingest all resources from all files
        all_resources: Dict[str, TerraformResource] = {}
        for tf_file in tf_files:
            file_res = self.parse_file(tf_file)
            all_resources.update(file_res)

        # Phase 2: Resolve references against all discovered resources
        known_ids = set(all_resources.keys())
        for res_id, res in all_resources.items():
            # Inferred references from attributes
            raw_refs = ReferenceExtractor.extract_from_value(res.attributes)
            # Filter candidate references to known resources in the project
            valid_refs = {r for r in raw_refs if r in known_ids and r != res_id}
            res.inferred_dependencies = valid_refs

            # Filter explicit depends_on
            res.explicit_dependencies = {
                dep for dep in res.explicit_dependencies if dep in known_ids and dep != res_id
            }

        self.resources = all_resources
        return all_resources

    def _extract_resources(self, parsed: dict, file_path: str) -> Dict[str, TerraformResource]:
        """Extracts resources from a parsed HCL dictionary."""
        extracted: Dict[str, TerraformResource] = {}
        raw_resources = parsed.get("resource", [])

        for res_block in raw_resources:
            for res_type, instances in res_block.items():
                for instance_name, config in instances.items():
                    res_id = f"{res_type}.{instance_name}"
                    explicit_deps = ReferenceExtractor.extract_explicit_depends_on(config)

                    res = TerraformResource(
                        id=res_id,
                        resource_type=res_type,
                        name=instance_name,
                        file_path=file_path,
                        attributes=config,
                        explicit_dependencies=explicit_deps,
                        inferred_dependencies=set(),
                    )
                    extracted[res_id] = res

        return extracted
