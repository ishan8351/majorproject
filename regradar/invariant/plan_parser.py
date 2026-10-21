import json
from pathlib import Path
from typing import Any, Dict, List, Union

from regradar.invariant.models import ResourceChange


class PlanParser:
    """
    Parses Terraform / OpenTofu execution plan JSON outputs (from `tofu show -json`).
    """

    @classmethod
    def parse_json_file(cls, file_path: Union[str, Path]) -> List[ResourceChange]:
        """Reads and parses a saved plan JSON file."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Plan file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return cls.parse_json_dict(data)

    @classmethod
    def parse_json_str(cls, json_str: str) -> List[ResourceChange]:
        """Parses a plan JSON string."""
        data = json.loads(json_str)
        return cls.parse_json_dict(data)

    @classmethod
    def parse_json_dict(cls, data: Dict[str, Any]) -> List[ResourceChange]:
        """Extracts all resource changes from parsed JSON data."""
        raw_changes = data.get("resource_changes", [])
        changes: List[ResourceChange] = []

        for item in raw_changes:
            change_data = item.get("change", {})
            actions = change_data.get("actions", ["no-op"])
            action_reason = item.get("action_reason") or change_data.get("action_reason")

            resource_change = ResourceChange(
                address=item.get("address", ""),
                resource_type=item.get("type", ""),
                name=item.get("name", ""),
                actions=actions,
                action_reason=action_reason,
                before=change_data.get("before"),
                after=change_data.get("after"),
                after_unknown=change_data.get("after_unknown"),
            )
            changes.append(resource_change)

        return changes
