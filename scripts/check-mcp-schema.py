# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0"]
# ///
"""Compare strict MCP validation with an in-memory no-extensions control.

Usage: uv run scripts/check-mcp-schema.py SCHEMA_JSON MCP_JSON
Neither input is modified. This checks JSON shape, not host support or OAuth.
"""

import argparse
import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("schema", type=Path)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    schema = json.loads(args.schema.read_text(encoding="utf-8-sig"))
    config = json.loads(args.config.read_text(encoding="utf-8-sig"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    original_valid = validator.is_valid(config)
    # This control deliberately omits client-specific auth configuration.
    # It must never be presented as a validated production OAuth configuration.
    control = copy.deepcopy(config)
    removed = []
    for name, server in control.get("mcpServers", {}).items():
        if isinstance(server, dict) and "extensions" in server:
            del server["extensions"]
            removed.append(name)
    print(json.dumps({
        "schema": schema.get("$id"),
        "original_valid": original_valid,
        "control_without_server_extensions_valid": validator.is_valid(control),
        "control_removed_extensions_from_servers": removed,
        "inputs_modified": False,
        "oauth_or_host_loading_verified": False,
    }, indent=2))
    return 0 if original_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
