import re
from typing import Any, List, Set


class ReferenceExtractor:
    """
    Extracts cross-resource references and explicit dependencies from Terraform HCL AST.
    Supports deep attribute extraction across complex expressions, module outputs,
    and data sources.
    """

    # Matches patterns like aws_vpc.main.id, data.aws_ami.ubuntu.id, module.vpc.subnet_id
    REF_PATTERN = re.compile(
        r"([a-zA-Z_][a-zA-Z0-9_-]*(?:\.[a-zA-Z_][a-zA-Z0-9_-]*)+)"
    )

    # Matches variable references like var.vpc_cidr or ${var.vpc_cidr}
    VAR_PATTERN = re.compile(
        r"(?:\$\{)?\bvar\.([a-zA-Z_][a-zA-Z0-9_-]*)\b(?:\})?"
    )

    # Built-in prefixes that are not other managed resources
    IGNORED_PREFIXES = {"var.", "local.", "count.", "each.", "path.", "terraform."}

    @classmethod
    def _sanitize(cls, val: Any) -> str:
        """Strips surrounding whitespace and quotes."""
        if val is None:
            return ""
        s = str(val).strip()
        while len(s) >= 2 and ((s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'"))):
            s = s[1:-1].strip()
        return s

    @classmethod
    def _extract_from_token(cls, token: str) -> Set[str]:
        """Parses a single dotted identifier token into resource/module/data candidate IDs."""
        cleaned = cls._sanitize(token)
        if any(cleaned.startswith(prefix) for prefix in cls.IGNORED_PREFIXES):
            return set()

        parts = cleaned.split(".")
        if len(parts) < 2:
            return set()

        refs: Set[str] = set()

        # Case 1: Data sources (data.<type>.<name>[.<attr>...])
        if parts[0] == "data":
            if len(parts) >= 3:
                refs.add(f"data.{parts[1]}.{parts[2]}")
            else:
                refs.add(f"data.{parts[1]}")
            return refs

        # Case 2: Modules (module.<mod>[.module.<child_mod>...][.<output_or_res>...])
        if parts[0] == "module":
            i = 0
            prefix_parts = []
            while i < len(parts) and parts[i] == "module":
                if i + 1 < len(parts):
                    prefix_parts.extend([parts[i], parts[i + 1]])
                    i += 2
                else:
                    break

            mod_prefix = ".".join(prefix_parts)
            rem = parts[i:]

            if mod_prefix:
                refs.add(mod_prefix)
                if len(rem) == 1:
                    # module.vpc.subnet_id -> output reference
                    refs.add(f"{mod_prefix}.{rem[0]}")
                elif len(rem) >= 2:
                    if rem[0] == "data" and len(rem) >= 3:
                        # module.vpc.data.aws_ami.ubuntu.id
                        refs.add(f"{mod_prefix}.data.{rem[1]}.{rem[2]}")
                    else:
                        # module.vpc.aws_subnet.public.id or module.vpc.subnet_id.something
                        refs.add(f"{mod_prefix}.{rem[0]}")
                        refs.add(f"{mod_prefix}.{rem[0]}.{rem[1]}")
            return refs

        # Case 3: Standard managed resource (<type>.<name>[.<attr>...])
        # Supports multi-cloud providers (aws_*, azurerm_*, google_*, kubernetes_*, etc.)
        refs.add(f"{parts[0]}.{parts[1]}")
        return refs

    @classmethod
    def extract_from_value(cls, val: Any) -> Set[str]:
        """
        Recursively traverses arbitrary HCL values and extracts candidate references.
        Supports complex expressions (ternaries, lists, dicts, indexing, splats).
        """
        refs: Set[str] = set()

        if isinstance(val, str):
            matches = cls.REF_PATTERN.findall(val)
            for m in matches:
                refs.update(cls._extract_from_token(m))

        elif isinstance(val, list):
            for item in val:
                refs.update(cls.extract_from_value(item))

        elif isinstance(val, dict):
            for v in val.values():
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
                    matches = cls.REF_PATTERN.findall(item)
                    for token in matches:
                        depends.update(cls._extract_from_token(token))
                elif isinstance(item, list):
                    depends.update(cls.extract_explicit_depends_on({"depends_on": item}))
        elif isinstance(raw, str):
            matches = cls.REF_PATTERN.findall(raw)
            for token in matches:
                depends.update(cls._extract_from_token(token))

        return depends

    @classmethod
    def extract_variables(cls, val: Any) -> Set[str]:
        """
        Recursively extracts variable names referenced in expressions
        (e.g. var.vpc_cidr or ${var.vpc_cidr} -> 'vpc_cidr').
        """
        vars_found: Set[str] = set()

        if isinstance(val, str):
            matches = cls.VAR_PATTERN.findall(val)
            for m in matches:
                clean = cls._sanitize(m)
                if clean:
                    vars_found.add(clean)
        elif isinstance(val, list):
            for item in val:
                vars_found.update(cls.extract_variables(item))
        elif isinstance(val, dict):
            for v in val.values():
                vars_found.update(cls.extract_variables(v))

        return vars_found
