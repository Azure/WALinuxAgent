"""
Step 7 — Inject a deterministic Component Mapping table into copilot-instructions.md.

Reads:
  - scripts/dag-enrichment/compose_to_dag_mapping-symbols.json (from step 3)

Updates (idempotent, preserves all other content):
  - .github/copilot-instructions.md

What it does
------------
Generates a markdown table that maps every source directory the DAG pipeline
clustered into a tier-1/tier-2 DAG doc, then writes that table into a
marker-bounded section of ``.github/copilot-instructions.md``:

    <!-- AUTO-GENERATED-MAPPING:BEGIN  (managed by step7_inject_routing_table.py) -->
    ...table...
    <!-- AUTO-GENERATED-MAPPING:END -->

On subsequent runs, only the content between the markers is replaced.
First-time runs insert the block right before a stable anchor heading
(default: ``## Hard Rules``), or append it to the end of the file if no
anchor is found.

Why this exists
---------------
Hand-crafted ownership tables in copilot-instructions.md drift the moment a
new DAG is added or refactored. The pipeline already knows every source
directory each DAG covers (in the mapping JSON produced by step 3), so this
script turns that JSON into the exact routing the agent needs:

    | source path pattern |
    | -> copilot-docs/{layer}/{name}.md
    | -> intermediate-docs/{layer}/{name}.content.md
    | (see also: cross-referenced DAGs)
    | description from cluster labeling

Agents loading copilot-instructions.md as a system-prompt preamble will see
this table at the top, eliminating exploratory ``list_dir`` calls and pushing
the agent straight to the right tier-1 doc for the source path it's looking at.

Differs from step 6
-------------------
``step6_generate_copilot_instructions.py`` synthesises the WHOLE
copilot-instructions.md from scratch via the LLM (intended for first-time
bootstrap on a brand-new repo). This script is purely deterministic — it only
manages the auto-generated section between the markers. They are complementary:
run step 6 once to bootstrap, then step 7 on every DAG regeneration to refresh
the table.

Usage
-----
    python scripts/dag-enrichment/step7_inject_routing_table.py

    # Custom mapping JSON (e.g. if multiple clustering approaches coexist):
    python scripts/dag-enrichment/step7_inject_routing_table.py \
        --mapping scripts/dag-enrichment/compose_to_dag_mapping-symbols.json

    # Target a different instructions file:
    python scripts/dag-enrichment/step7_inject_routing_table.py \
        --instructions .github/copilot-instructions.md

    # Preview without writing:
    python scripts/dag-enrichment/step7_inject_routing_table.py --dry-run

    # Pick a different anchor for first-time insertion:
    python scripts/dag-enrichment/step7_inject_routing_table.py \
        --anchor "## Architecture Rules"

    # Cap rows-per-table to avoid blowing the preamble budget:
    python scripts/dag-enrichment/step7_inject_routing_table.py --max-prefix-groups 5
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

DEFAULT_MAPPING = REPO_ROOT / "scripts" / "dag-enrichment" / "compose_to_dag_mapping-symbols.json"
DEFAULT_INSTRUCTIONS = REPO_ROOT / ".github" / "copilot-instructions.md"

BEGIN_MARKER = "<!-- AUTO-GENERATED-MAPPING:BEGIN  (managed by step7_inject_routing_table.py) -->"
END_MARKER = "<!-- AUTO-GENERATED-MAPPING:END -->"

# Default anchor headings to try when inserting for the first time. The block
# goes RIGHT BEFORE the first matching heading. If none match, we append.
DEFAULT_ANCHOR_CANDIDATES = (
    "## Hard Rules",
    "## Architecture Rules",
    "## Coding Conventions",
    "## Response Style",
    "## Auto-Trigger Rules",
)


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def _tier_paths_from_dag(dag_doc_new: str) -> tuple[str, str]:
    """Map 'L1-conceptual/foo.md' -> (tier1_path, tier2_path)."""
    layer, name = dag_doc_new.split("/", 1)
    tier1 = f"copilot-docs/{layer}/{name}"
    tier2_name = re.sub(r"\.md$", ".content.md", name)
    tier2 = f"intermediate-docs/{layer}/{tier2_name}"
    return tier1, tier2


def _short_dag_name(dag_doc_new: str) -> str:
    """'L1-conceptual/backup-agent-contracts.md' -> 'L1-conceptual/backup-agent-contracts'."""
    return re.sub(r"\.md$", "", dag_doc_new)


def _aggregate_compose_dirs(
    dirs: list[str], *, max_groups: int = 6, prefix_segments: int = 3,
) -> list[str]:
    """Collapse a long list of compose_dirs into a few path patterns.

    Strategy:
      - Bucket directories that share the same first ``prefix_segments`` path
        segments.
      - If a bucket has 1 entry, emit the full path verbatim.
      - If a bucket has 2+ entries, emit ``prefix/**`` (precise enough; agent
        can glob-match a path against the pattern).
      - Cap output at ``max_groups`` rows; remaining buckets are summarised as
        ``*(+N more)*``.
    """
    if not dirs:
        return []
    buckets: dict[str, list[str]] = defaultdict(list)
    for d in dirs:
        key = "/".join(d.rstrip("/").split("/")[:prefix_segments])
        buckets[key].append(d.rstrip("/"))

    ordered = sorted(buckets.items(), key=lambda x: (-len(x[1]), x[0]))
    out: list[str] = []
    overflow = 0
    for i, (key, members) in enumerate(ordered):
        if i >= max_groups:
            overflow += len(members)
            continue
        if len(members) == 1:
            out.append(f"`{members[0]}/`")
        else:
            out.append(f"`{key}/**`")
    if overflow:
        out.append(f"*(+{overflow} more)*")
    return out


def _render_xrefs(xrefs: list[str], limit: int = 4) -> str:
    if not xrefs:
        return ""
    names = [_short_dag_name(x).rsplit("/", 1)[-1] for x in xrefs[:limit]]
    suffix = f", +{len(xrefs) - limit} more" if len(xrefs) > limit else ""
    return f"<br>*(see also: {', '.join(names)}{suffix})*"


# ---------------------------------------------------------------------------
# Table builder
# ---------------------------------------------------------------------------

def build_table(mappings: list[dict], *, max_prefix_groups: int = 6) -> str:
    """Render the full markdown block (heading + intro + table)."""
    lines: list[str] = []
    lines.append("## Component Mapping (auto-generated)")
    lines.append("")
    lines.append(
        "_This section is generated deterministically from "
        "`scripts/dag-enrichment/compose_to_dag_mapping-symbols.json` "
        "(by `step7_inject_routing_table.py`). Do not hand-edit - it is rewritten "
        "on every DAG regeneration. Anything outside the AUTO-GENERATED-MAPPING "
        "markers in this file is preserved._"
    )
    lines.append("")
    lines.append(
        "**How to use this table** — the table answers three kinds of lookups, not just path lookups:\n"
        "\n"
        "1. **Path lookup**: if the question (or your investigation) mentions a source path, find the row "
        "whose pattern matches and follow its reading chain.\n"
        "2. **Symbol / class lookup**: if the question names a class, interface, method, error code, "
        "config key, or feature (e.g. *FsmBlock*, *BackupTaskController*, *PreBackupBlock*), scan the "
        "**What it covers** column for that term. Each description names the symbols and concepts the DAG "
        "covers because the cluster was built from those very symbols.\n"
        "3. **Concept lookup**: for broader concepts (e.g. *backup workflow*, *plugin lifecycle*, "
        "*cross-platform helpers*), the **What it covers** column groups related areas. Pick the row that "
        "best matches; follow the reading chain; use the `(see also: ...)` cross-references to find adjacent DAGs.\n"
        "\n"
        "In every case the reading chain is the same: open the compact `copilot-docs/` doc first, then its "
        "`intermediate-docs/{layer}/{name}.content.md` companion. Only read source code if both tiers are insufficient."
    )
    lines.append("")
    lines.append("| Source path pattern | Reading chain (tier-1 -> tier-2) | What it covers |")
    lines.append("|---------------------|----------------------------------|----------------|")

    for m in sorted(mappings, key=lambda x: x["dag_doc_new"]):
        dag = m["dag_doc_new"]
        tier1, tier2 = _tier_paths_from_dag(dag)
        compose = _aggregate_compose_dirs(
            m.get("compose_dirs") or [], max_groups=max_prefix_groups,
        )
        pattern_cell = "<br>".join(compose) if compose else "_(no compose dirs)_"
        chain = f"`{tier1}` -> `{tier2}`{_render_xrefs(m.get('cross_referenced_dags') or [])}"
        desc = (m.get("description") or "").strip().replace("|", "\\|")
        lines.append(f"| {pattern_cell} | {chain} | {desc} |")

    lines.append("")
    lines.append(
        "**Coverage gap rule:** if your source path matches no row above, no DAG "
        "doc covers that area. Say so explicitly in your answer and cite the "
        "source file(s) you used. Do not silently substitute an unrelated doc."
    )

    # ---- Second sub-table: namespace → DAG (concept/symbol index) ----
    # When the user mentions a class / interface / type without a path
    # (very common: "how does FsmBlock work?"), the agent scans this
    # smaller table to find the owning DAG.
    ns_rows = []
    for m in mappings:
        primary = (m.get("defining_namespace") or "").strip()
        if not primary:
            continue
        dag = m["dag_doc_new"]
        tier1, _tier2 = _tier_paths_from_dag(dag)
        desc = (m.get("description") or "").strip()
        # Use last 2 segments of the namespace as the "concept" — typically
        # the meaningful classifier (e.g. .Service.Fsm -> "Service.Fsm")
        ns_segments = primary.split(".")
        short = ".".join(ns_segments[-2:]) if len(ns_segments) >= 2 else primary
        ns_rows.append((primary, short, tier1, desc))

    if ns_rows:
        lines.append("")
        lines.append("### Defining namespace -> DAG (concept / symbol index)")
        lines.append("")
        lines.append(
            "Use this table when the user prompt names a **class, interface, type, "
            "or namespace** without giving you a source path. Scan the namespace "
            "and short-name columns for the term. Each entry's reading chain is the "
            "same as in the path table above (tier-1 -> tier-2)."
        )
        lines.append("")
        lines.append("| Defining namespace | Short | Tier-1 doc | What it covers |")
        lines.append("|--------------------|-------|------------|----------------|")
        for primary, short, tier1, desc in sorted(ns_rows, key=lambda r: r[0]):
            primary_cell = f"`{primary}`"
            short_cell = f"`{short}`"
            desc_cell = desc.replace("|", "\\|")
            lines.append(
                f"| {primary_cell} | {short_cell} | `{tier1}` | {desc_cell} |"
            )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# File injection
# ---------------------------------------------------------------------------

def inject_block(
    file_path: Path, block_body: str, *, anchor_candidates: tuple[str, ...],
) -> tuple[str, str]:
    """Return (new_content, action_taken) where action is 'replaced' | 'inserted' | 'appended'."""
    bounded = f"{BEGIN_MARKER}\n\n{block_body}\n\n{END_MARKER}"

    if not file_path.exists():
        # First-ever write: just create the file containing only the block.
        return bounded + "\n", "created"

    content = file_path.read_text(encoding="utf-8")

    # Replace existing block if markers are present.
    if BEGIN_MARKER in content and END_MARKER in content:
        pattern = re.compile(
            re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER),
            re.DOTALL,
        )
        new_content = pattern.sub(bounded.replace("\\", "\\\\"), content)
        return new_content, "replaced"

    # Otherwise insert before the first matching anchor heading.
    for anchor in anchor_candidates:
        idx = content.find(anchor)
        if idx != -1:
            before = content[:idx].rstrip() + "\n\n"
            after = content[idx:]
            return before + bounded + "\n\n" + after, f"inserted (before '{anchor.strip()}')"

    # Last resort: append.
    sep = "\n\n" if not content.endswith("\n\n") else ""
    return content + sep + bounded + "\n", "appended"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--mapping",
        type=Path,
        default=DEFAULT_MAPPING,
        help=f"Path to the DAG mapping JSON (default: {DEFAULT_MAPPING.relative_to(REPO_ROOT)})",
    )
    p.add_argument(
        "--instructions",
        type=Path,
        default=DEFAULT_INSTRUCTIONS,
        help=f"Path to the copilot-instructions.md file to update (default: {DEFAULT_INSTRUCTIONS.relative_to(REPO_ROOT)})",
    )
    p.add_argument(
        "--anchor",
        action="append",
        default=None,
        help="Heading to insert BEFORE on first run. Repeatable; tries each in order. "
        "Defaults: " + ", ".join(repr(a) for a in DEFAULT_ANCHOR_CANDIDATES),
    )
    p.add_argument(
        "--max-prefix-groups",
        type=int,
        default=6,
        help="Cap on path-pattern rows aggregated per DAG (default 6). "
        "Lower = more compact table, higher = more granular.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the rendered block to stdout and exit without writing.",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()

    if not args.mapping.is_file():
        print(f"ERROR: mapping JSON not found at {args.mapping}", file=sys.stderr)
        print("Run step 3 first: python scripts/dag-enrichment/step3_generate_mapping.py", file=sys.stderr)
        return 1

    data = json.loads(args.mapping.read_text(encoding="utf-8"))
    mappings = data.get("mappings") or []
    if not mappings:
        print(f"ERROR: no 'mappings' array found in {args.mapping}", file=sys.stderr)
        return 1

    block = build_table(mappings, max_prefix_groups=args.max_prefix_groups)

    if args.dry_run:
        print(block)
        print(f"\n--- DRY RUN: would update {args.instructions} ---", file=sys.stderr)
        print(f"--- rows: {len(mappings)}, block bytes: {len(block):,} ---", file=sys.stderr)
        return 0

    anchors = tuple(args.anchor) if args.anchor else DEFAULT_ANCHOR_CANDIDATES
    new_content, action = inject_block(
        args.instructions, block, anchor_candidates=anchors,
    )

    args.instructions.parent.mkdir(parents=True, exist_ok=True)
    args.instructions.write_text(new_content, encoding="utf-8")

    print(
        f"OK  {action}: {args.instructions.relative_to(REPO_ROOT) if args.instructions.is_absolute() else args.instructions}",
        file=sys.stderr,
    )
    print(
        f"    rows={len(mappings)}  block_bytes={len(block):,}  total_file_bytes={len(new_content):,}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
