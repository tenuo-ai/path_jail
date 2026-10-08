#!/usr/bin/env python3
"""Keep Rust code blocks in the docs identical to compiled examples.

Every ```rust block in the checked Markdown files must be one of:

* preceded by `<!-- example: doc-examples/examples/<file>.rs#<anchor> -->`
  and identical to the region between `// ANCHOR: <anchor>` and
  `// ANCHOR_END: <anchor>` in that file (common indentation removed), or
* marked ```rust,ignore: an intentionally incomplete illustration.

Every anchor in doc-examples/examples must be used by some block, so compiled
examples cannot silently drift away from the docs. CI builds those files.

Usage:
    scripts/check_doc_examples.py          check, exit 1 on any problem
    scripts/check_doc_examples.py --fix    rewrite linked doc blocks from the examples
"""

from __future__ import annotations

import difflib
import re
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", *sorted((ROOT / "docs" / "guides").glob("*.md"))]
EXAMPLES = ROOT / "doc-examples" / "examples"

FENCE = re.compile(r"^```(?P<info>[^\n]*)\n(?P<body>.*?)^```[ \t]*$", re.M | re.S)
MARKER = re.compile(r"<!--\s*example:\s*(?P<path>[^#\s]+)#(?P<anchor>[\w-]+)\s*-->\s*$")
ANCHOR = re.compile(r"^\s*// ANCHOR: (?P<name>[\w-]+)\s*$")
ANCHOR_END = re.compile(r"^\s*// ANCHOR_END: (?P<name>[\w-]+)\s*$")


def anchors(path: Path) -> dict[str, str]:
    """Map anchor name to its dedented region in `path`."""
    regions: dict[str, list[str]] = {}
    open_names: list[str] = []
    for line in path.read_text().splitlines():
        if m := ANCHOR.match(line):
            open_names.append(m["name"])
            regions[m["name"]] = []
            continue
        if m := ANCHOR_END.match(line):
            open_names.remove(m["name"])
            continue
        for name in open_names:
            regions[name].append(line)
    if open_names:
        raise SystemExit(f"{path}: unclosed ANCHOR {open_names}")
    return {name: textwrap.dedent("\n".join(lines)).strip("\n") for name, lines in regions.items()}


def main() -> int:
    fix = "--fix" in sys.argv[1:]
    errors: list[str] = []
    rewrites: dict[Path, list[tuple[int, int, str]]] = {}
    used: set[tuple[Path, str]] = set()
    cache: dict[Path, dict[str, str]] = {}

    for doc in DOCS:
        text = doc.read_text()
        for block in FENCE.finditer(text):
            info = block["info"].strip()
            lang = re.split(r"[,\s]", info, maxsplit=1)[0]
            if lang != "rust":
                continue
            line_no = text.count("\n", 0, block.start()) + 1
            where = f"{doc.relative_to(ROOT)}:{line_no}"
            if "ignore" in info.split(","):
                continue
            preceding = text[: block.start()].rstrip("\n").rsplit("\n", 1)[-1]
            marker = MARKER.search(preceding)
            if not marker:
                errors.append(
                    f"{where}: rust block is not linked to a compiled example. Add "
                    "`<!-- example: doc-examples/examples/<file>.rs#<anchor> -->` on the "
                    "line above, or mark it ```rust,ignore if it is an illustration."
                )
                continue
            source = (ROOT / marker["path"]).resolve()
            if not source.is_file():
                errors.append(f"{where}: example file {marker['path']} does not exist")
                continue
            regions = cache.setdefault(source, anchors(source))
            anchor = marker["anchor"]
            if anchor not in regions:
                errors.append(f"{where}: {marker['path']} has no ANCHOR {anchor!r}")
                continue
            used.add((source, anchor))
            expected = regions[anchor]
            actual = block["body"].strip("\n")
            if actual != expected and fix:
                rewrites.setdefault(doc, []).append(
                    (block.start("body"), block.end("body"), expected + "\n")
                )
                continue
            if actual != expected:
                diff = "\n".join(
                    difflib.unified_diff(
                        expected.splitlines(),
                        actual.splitlines(),
                        f"{marker['path']}#{anchor}",
                        where,
                        lineterm="",
                    )
                )
                errors.append(f"{where}: block differs from {marker['path']}#{anchor}\n{diff}")

    for source in sorted(EXAMPLES.glob("*.rs")):
        for anchor in cache.setdefault(source, anchors(source)):
            if (source, anchor) not in used:
                errors.append(f"{source.relative_to(ROOT)}: ANCHOR {anchor!r} is not used by any doc")

    for doc, edits in rewrites.items():
        text = doc.read_text()
        for start, end, body in sorted(edits, reverse=True):
            text = text[:start] + body + text[end:]
        doc.write_text(text)
        print(f"fixed: {len(edits)} block(s) in {doc.relative_to(ROOT)}")

    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"ok: {len(used)} doc blocks match compiled examples in {len(DOCS)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
