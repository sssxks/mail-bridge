# /// script
# requires-python = ">=3.11"
# dependencies = ["tree-sitter==0.26.0", "tree-sitter-rust==0.24.2"]
# ///
"""Check Rustdoc coverage for named public and private production declarations.

Run with `uv run scripts/check-rust-docs.py` from any working directory. Cargo's
missing_docs lint covers the exported API; this syntax check also covers private
types, functions, fields and enum variants. Unit-test modules and integration-test
trees are excluded. Tuple-field encodings are documented on their enclosing type.
"""

from pathlib import Path
import sys

from tree_sitter import Language, Parser
import tree_sitter_rust


ROOT = Path(__file__).resolve().parents[1]
DECLARATIONS = {
    "function_item", "function_signature_item", "struct_item", "enum_item",
    "enum_variant", "field_declaration", "trait_item", "type_item",
    "associated_type", "const_item", "static_item", "mod_item",
}


def inspect(path: Path, parser: Parser) -> tuple[int, list[str]]:
    """Count declarations and report undocumented names outside unit-test modules."""
    source = path.read_bytes()
    root = parser.parse(source).root_node
    relative = path.relative_to(ROOT).as_posix()
    problems = []
    if root.has_error:
        problems.append(f"{relative}: Rust syntax could not be parsed")
    count = 0

    def visit(node):
        nonlocal count
        previous = node.prev_named_sibling
        documented = False
        while previous and previous.type in {"attribute_item", "line_comment", "block_comment"}:
            text = source[previous.start_byte:previous.end_byte].decode("utf-8")
            if previous.type == "attribute_item" and "cfg(test)" in text:
                return
            documented |= text.startswith(("///", "/**"))
            previous = previous.prev_named_sibling
        name = node.child_by_field_name("name")
        if node.type in DECLARATIONS and name is not None:
            count += 1
            if not documented:
                spelling = source[name.start_byte:name.end_byte].decode("utf-8")
                problems.append(f"{relative}:{node.start_point.row + 1}: missing Rustdoc for {spelling}")
        for child in node.named_children:
            visit(child)

    visit(root)
    return count, problems


def main() -> int:
    """Inspect workspace production source and return a failing status for omissions."""
    parser = Parser(Language(tree_sitter_rust.language()))
    total = 0
    failures = []
    paths = sorted((ROOT / "crates").glob("*/src/**/*.rs"))
    for path in paths:
        count, problems = inspect(path, parser)
        total += count
        failures.extend(problems)
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Rustdoc coverage: {total} named production declarations in {len(paths)} files; no omissions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
