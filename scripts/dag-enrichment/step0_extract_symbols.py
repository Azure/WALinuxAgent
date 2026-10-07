"""
Step 0 (Symbols): Extract namespaces from compose summaries for namespace-based clustering.

For each supported source compose summary:
  1. Extracts ## Symbols section
  2. Identifies the DEFINING namespace (where the file's own class lives)
  3. Identifies IMPORTED namespaces (referenced/used by the file)
  4. Saves metadata for step1_namespace_clustering.py

Usage:
    python scripts/dag-enrichment/step0_extract_symbols.py

Output:
    scripts/dag-enrichment/output/clustering/symbols/
        file_metadata.json    (file_path -> {defining_ns, imported_ns, symbols})
        file_list.json        (sorted file paths)
        namespace_stats.json  (namespace -> file count, for inspection)
"""

import json
import re
import sys
import fnmatch
from pathlib import Path
from collections import Counter

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from dag_utils import detect_compose_base

OUTPUT_DIR = Path(__file__).resolve().parent / "output" / "clustering" / "symbols"

IGNORED_PATTERNS = [
    "*/obj/*", "*/bin/*", "*project.nuget.cache.md",
    "*.nuget.g.props.md", "*.nuget.g.targets.md",
    "*/owners.txt.md",
]

ALLOWED_EXTENSIONS = [
    ".cs.md",
    ".c.md",
    ".cc.md",
    ".cpp.md",
    ".h.md",
    ".hpp.md",
    ".py.md",
    ".rs.md",
]

# Use full namespace depth — no truncation. step1_namespace_clustering.py
# will handle merging clusters at appropriate levels.
NAMESPACE_DEPTH = 99


def should_ignore(rel_path: str) -> bool:
    for pattern in IGNORED_PATTERNS:
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(rel_path.split("/")[-1], pattern):
            return True
    return False


def is_source_file(rel_path: str) -> bool:
    return any(rel_path.endswith(ext) for ext in ALLOWED_EXTENSIONS)


def extract_symbols(content: str) -> list[str]:
    """Extract ## Symbols list from compose summary."""
    pattern = r"^## Symbols\s*\n(.*?)(?=^## |\Z)"
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    if not match:
        return []
    symbols = []
    for line in match.group(1).strip().split("\n"):
        line = line.strip()
        if line.startswith("- `") and line.endswith("`"):
            symbols.append(line[3:-1])
        elif line.startswith("- "):
            symbols.append(line[2:])
    return symbols


def truncate_namespace(ns: str, depth: int) -> str:
    """Truncate a fully-qualified name to the given depth.
    'A.B.C.D.E.F' at depth=4 → 'A.B.C.D'"""
    parts = ns.split(".")
    return ".".join(parts[:min(depth, len(parts))])


def classify_symbol(symbol: str, filename_stem: str) -> str:
    """Classify a symbol as 'defining' or 'imported'.
    A symbol is 'defining' if its last segment matches the file's class name."""
    parts = symbol.split(".")
    last = parts[-1] if parts else ""
    # The file's class name (without .cs.md)
    class_name = filename_stem.replace(".cs", "").replace(".Windows", "").replace(".Linux", "")

    # Check if this symbol defines the class or is a member of it
    if last == class_name or (len(parts) >= 2 and parts[-2] == class_name):
        return "defining"
    return "imported"


def extract_namespaces_from_symbols(symbols: list[str], filename_stem: str, depth: int) -> tuple[set[str], set[str]]:
    """Extract defining and imported namespace prefixes from symbol list.
    Returns (defining_namespaces, imported_namespaces)."""
    defining = set()
    imported = set()

    for sym in symbols:
        parts = sym.split(".")
        if len(parts) < 2:
            continue

        ns_prefix = truncate_namespace(sym, depth)
        if len(ns_prefix.split(".")) < 2:
            continue  # Skip single-segment names

        classification = classify_symbol(sym, filename_stem)
        if classification == "defining":
            defining.add(ns_prefix)
        else:
            imported.add(ns_prefix)

    # If no defining found, use the most specific namespace from any symbol
    if not defining and symbols:
        # Use the namespace of the first PascalCase class-like symbol
        for sym in symbols:
            parts = sym.split(".")
            if len(parts) >= 3 and parts[-1][0].isupper():
                ns = truncate_namespace(".".join(parts[:-1]), depth)
                if len(ns.split(".")) >= 2:
                    defining.add(ns)
                    break

    # Remove defining namespaces from imported (they're the same component)
    imported -= defining

    return defining, imported


def main():
    # Parse --compose-base CLI override
    compose_base_override = None
    for i, arg in enumerate(sys.argv):
        if arg == "--compose-base" and i + 1 < len(sys.argv):
            compose_base_override = sys.argv[i + 1]
    COMPOSE_BASE = detect_compose_base(REPO_ROOT, compose_base_override)
    print(f"Compose base: {COMPOSE_BASE}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_files = sorted(COMPOSE_BASE.rglob("*.md"))
    print(f"Found {len(all_files)} compose summary files")

    all_file_namespaces = {}  # file_path -> {defining: set, imported: set, symbols: list}
    skipped_ignore = 0
    skipped_not_source = 0
    skipped_no_symbols = 0

    for filepath in all_files:
        rel_path = str(filepath.relative_to(COMPOSE_BASE)).replace("\\", "/")

        if should_ignore(rel_path):
            skipped_ignore += 1
            continue
        if not is_source_file(rel_path):
            skipped_not_source += 1
            continue

        try:
            text = filepath.read_text(encoding="utf-8")
        except Exception:
            continue

        symbols = extract_symbols(text)
        if not symbols:
            skipped_no_symbols += 1
            continue

        filename_stem = filepath.stem  # e.g. "BackupBlock.cs"
        defining, imported = extract_namespaces_from_symbols(symbols, filename_stem, NAMESPACE_DEPTH)

        if not defining and not imported:
            skipped_no_symbols += 1
            continue

        all_file_namespaces[rel_path] = {
            "defining": defining,
            "imported": imported,
            "symbols": symbols[:15],  # Keep top 15 for metadata
        }

    print(f"\nFiles with namespaces:         {len(all_file_namespaces)}")
    print(f"Skipped (ignored):             {skipped_ignore}")
    print(f"Skipped (unsupported source):  {skipped_not_source}")
    print(f"Skipped (no symbols):          {skipped_no_symbols}")

    # Compute namespace stats
    ns_stats = Counter()
    defining_stats = Counter()
    for data in all_file_namespaces.values():
        for ns in data["defining"]:
            defining_stats[ns] += 1
        for ns in data["defining"] | data["imported"]:
            ns_stats[ns] += 1

    # Save metadata (convert sets to lists for JSON)
    metadata = {}
    for fp, data in all_file_namespaces.items():
        source_file = fp[:-3] if fp.endswith(".md") else fp
        metadata[fp] = {
            "defining_ns": sorted(data["defining"]),
            "imported_ns": sorted(data["imported"]),
            "all_ns": sorted(data["defining"] | data["imported"]),
            "symbols": data["symbols"],
            "source_file": source_file,
            "dir_path": "/".join(fp.split("/")[:-1]),
            "content_preview": "",
        }
    with open(OUTPUT_DIR / "file_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    with open(OUTPUT_DIR / "file_list.json", "w", encoding="utf-8") as f:
        json.dump(sorted(all_file_namespaces.keys()), f, indent=2)

    with open(OUTPUT_DIR / "namespace_stats.json", "w", encoding="utf-8") as f:
        json.dump({
            "total_defining_namespaces": len(defining_stats),
            "by_frequency": {ns: cnt for ns, cnt in ns_stats.most_common()},
            "defining_only": {ns: cnt for ns, cnt in defining_stats.most_common(30)},
        }, f, indent=2)

    print(f"\nTop 15 defining namespaces:")
    for ns, cnt in defining_stats.most_common(15):
        print(f"  {cnt:4d} files → {ns}")

    print(f"\nOutput: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
