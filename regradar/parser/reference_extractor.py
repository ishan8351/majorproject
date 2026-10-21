import re
from typing import Any, List, Set


class ReferenceExtractor:
    """
    Extracts cross-resource references and explicit dependencies from Terraform HCL AST.
    """

    # Matches patterns like aws_vpc.main.id, data.aws_ami.ubuntu.id, module.vpc.vpc_id
    REF_PATTERN = re.compile(
        r"(?:\$\{)?\b([a-zA-Z_][a-zA-Z0-9_-]*\.[a-zA-Z_][a-zA-Z0-9_-]*(?:\.[a-zA-Z_][a-zA-Z0-9_-]*)*)\b(?:\})?"
    )

    # Built-in prefixes that are not other managed resources
    IGNORED_PREFIXES = {"var.", "local.", "count.", "each.", "path.", "terraform."}

    @classmethod
    def extract_from_value(cls, val: Any) -> Set[str]:
        """Recursively traverses arbitrary HCL values and extracts candidate references."""
        refs: Set[str] = set()

        if isinstance(val, str):
            # Clean string interpolations: remove ${ and } wrappers
            matches = cls.REF_PATTERN.findall(val)
            for m in matches:
                # Discard ignored built-ins
                if any(m.startswith(prefix) for prefix in cls.IGNORED_PREFIXES):
                    continue

                parts = m.split(".")
                if parts[0] == "data" and len(parts) >= 3:
                    # data.aws_ami.ubuntu
                    refs.add(f"data.{parts[1]}.{parts[2]}")
                elif parts[0] == "module" and len(parts) >= 2:
                    # module.vpc
                    refs.add(f"module.{parts[1]}")
                elif len(parts) >= 2:
                    # aws_vpc.main
                    refs.add(f"{parts[0]}.{parts[1]}")

        elif isinstance(val, list):
            for item in val:
                refs.update(cls.extract_from_value(item))

        elif isinstance(val, dict):
            for k, v in val.items():
                refs.update(cls.extract_from_value(v))

        return refs

    @classmethod
    def extract_explicit_depends_on(cls, config: dict) -> Set[str]:
        """Extracts explicit `depends_on` resources from block config."""
        depends: Set[str] = set()
        raw = config.get("depends_on")
        if not raw:
            return depends

        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    cleaned = item.replace("${", "").replace("}", "").strip()
                    parts = cleaned.split(".")
                    if len(parts) >= 2:
                        depends.add(f"{parts[0]}.{parts[1]}")
                elif isinstance(item, list):
                    depends.update(cls.extract_explicit_depends_on({"depends_on": item}))
        elif isinstance(raw, str):
            cleaned = raw.replace("${", "").replace("}", "").strip()
            parts = cleaned.split(".")
            if len(parts) >= 2:
                depends.add(f"{parts[0]}.{parts[1]}")

        return depends
