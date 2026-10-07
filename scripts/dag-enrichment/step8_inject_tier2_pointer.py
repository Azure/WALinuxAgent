"""
Step 8 — Inject a tier-2 pointer banner into every tier-1 copilot-doc.

Reads / updates (idempotent, preserves all other content):
  - copilot-docs/**/*.md  (the compact tier-1 DAG docs)

What it does
------------
For every ``copilot-docs/{layer}/{name}.md`` that has a matching
``intermediate-docs/{layer}/{name}.content.md`` companion, inserts a short
banner right after the document's H1 title:

    <!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
    > **Need a specific class, method, error code, config key, or flow step?**
    > Read `intermediate-docs/{layer}/{name}.content.md` before answering — that
    > companion holds the per-file implementation detail. For a high-level
    > overview this compact doc is the right altitude; escalate only when the
    > question turns on a specific symbol or step.
    > The companion concatenates one `## <source/path>.cs` section per file and
    > can be large — don't read it whole: grep it for your target `.cs` name to
    > find its `## ` line, read only that range, and start with its *Purpose and
    > Functionality* sub-section.
    <!-- TIER2-POINTER:END -->

On subsequent runs the content between the markers is replaced (so re-running
after a doc regeneration keeps a single, up-to-date banner). Files WITHOUT a
matching tier-2 companion (e.g. ``docs-index.md`` navigation stubs) are left
untouched.

Why this exists
---------------
The agent-sim benchmark showed agents reliably reach the right *tier-1* doc
(thanks to the routing table from step 7) but then declare it "sufficient" and
skip the tier-2 ``.content.md`` companion — which is exactly where the
implementation detail lives. Surfacing the companion path at the very top of
every tier-1 doc nudges the agent (and real human users) to open it before
answering, lifting answer quality on detail-heavy questions.

This benefits REAL repo users too: anyone reading a compact ``copilot-docs/``
file sees the pointer to its richer companion immediately.

Usage
-----
    python scripts/dag-enrichment/step8_inject_tier2_pointer.py
    python scripts/dag-enrichment/step8_inject_tier2_pointer.py --dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Resolve repo root: this file lives at <repo>/scripts/dag-enrichment/ OR
# <repo>/.github/skills/dag-generation/references/. Walk up to find a dir that
# contains both copilot-docs/ and intermediate-docs/.
def _find_repo_root(start: Path) -> Path:
    for parent in [start, *start.parents]:
        if (parent / "copilot-docs").is_dir() and (parent / "intermediate-docs").is_dir():
            return parent
    # Fallback: 2 levels up from scripts/dag-enrichment/
    return start.parents[1]


BEGIN_MARKER = "<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->"
END_MARKER = "<!-- TIER2-POINTER:END -->"

_H1_RE = re.compile(r"^(#\s+.+?)\s*$", re.MULTILINE)
_BLOCK_RE = re.compile(
    re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER) + r"\n?",
    re.DOTALL,
)


def _tier2_rel_for(doc_rel_posix: str) -> str:
    """copilot-docs/L1-conceptual/foo.md -> intermediate-docs/L1-conceptual/foo.content.md"""
    # strip the leading 'copilot-docs/' and the '.md' suffix
    inner = doc_rel_posix[len("copilot-docs/"):]
    inner = re.sub(r"\.md$", ".content.md", inner)
    return f"intermediate-docs/{inner}"


def _banner(tier2_rel: str) -> str:
    return (
        f"{BEGIN_MARKER}\n"
        f"> **Need a specific class, method, error code, config key, or flow step?**\n"
        f"> Read `{tier2_rel}` before answering — that companion holds the per-file\n"
        f"> implementation detail. For a high-level overview this compact doc is the\n"
        f"> right altitude; escalate to the companion (then targeted source) only\n"
        f"> when the question turns on a specific symbol or step.\n"
        f"> The companion concatenates one `## <source/path>.cs` section per file and\n"
        f"> can be large — don't read it whole: `grep_search` it for your target `.cs`\n"
        f"> name to find its `## ` line, `read_file` only that range, and start with\n"
        f"> its *Purpose and Functionality* sub-section.\n"
        f"{END_MARKER}"
    )


def _inject(text: str, banner: str) -> tuple[str, str]:
    """Return (new_text, action). Idempotent: replaces an existing banner,
    else inserts right after the first H1, else prepends."""
    if BEGIN_MARKER in text and END_MARKER in text:
        new = _BLOCK_RE.sub(banner + "\n", text, count=1)
        return new, "replaced"

    m = _H1_RE.search(text)
    if m:
        insert_at = m.end()
        new = text[:insert_at] + "\n\n" + banner + text[insert_at:]
        return new, "inserted"

    # No H1 — prepend.
    return banner + "\n\n" + text, "prepended"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Report what would change without writing.")
    parser.add_argument("--repo-root", type=Path, default=None, help="Override repo root detection.")
    args = parser.parse_args()

    repo_root = (args.repo_root or _find_repo_root(Path(__file__).resolve())).resolve()
    docs_dir = repo_root / "copilot-docs"
    tier2_dir = repo_root / "intermediate-docs"

    if not docs_dir.is_dir():
        print(f"ERROR: copilot-docs/ not found under {repo_root}", file=sys.stderr)
        return 1
    if not tier2_dir.is_dir():
        print(f"ERROR: intermediate-docs/ not found under {repo_root}", file=sys.stderr)
        return 1

    injected = skipped_no_t2 = unchanged = 0
    for doc in sorted(docs_dir.rglob("*.md")):
        rel = doc.relative_to(repo_root).as_posix()
        tier2_rel = _tier2_rel_for(rel)
        if not (repo_root / tier2_rel).is_file():
            skipped_no_t2 += 1
            continue

        original = doc.read_text(encoding="utf-8")
        banner = _banner(tier2_rel)
        new, action = _inject(original, banner)
        if new == original:
            unchanged += 1
            continue
        injected += 1
        if args.dry_run:
            print(f"  would {action}: {rel}  ->  {tier2_rel}")
        else:
            doc.write_text(new, encoding="utf-8")

    verb = "would inject" if args.dry_run else "injected/updated"
    print(
        f"OK  {verb}={injected}  unchanged={unchanged}  "
        f"skipped_no_tier2={skipped_no_t2}  (repo: {repo_root})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
