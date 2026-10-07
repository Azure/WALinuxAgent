"""
Normalize machine-specific absolute paths in generated documentation.

Compose summaries embed the absolute on-disk path of each source file in their
``- Path:`` metadata (e.g. ``q:\\astred-bcdr-onboarding\\...\\src\\...``). When
those summaries are copied into the generated intermediate docs, they leak the
author's local checkout location. This script rewrites any such absolute path
that points inside the repo to a stable repository-relative path (``src\\...``).

The same normalization is applied at generation time by
``create_dags_from_mapping.py`` (via ``dag_utils.normalize_repo_paths``); this
script is a one-shot / re-runnable cleanup for docs that were generated before
that fix landed.

Usage:
    # Fix the default target (intermediate-docs/) in place
    python scripts/dag-enrichment/normalize_paths.py

    # Preview changes without writing
    python scripts/dag-enrichment/normalize_paths.py --dry-run

    # Target a specific directory or file
    python scripts/dag-enrichment/normalize_paths.py --path intermediate-docs
"""

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from dag_utils import normalize_repo_paths

DEFAULT_TARGET = REPO_ROOT / "intermediate-docs"
FILE_GLOB = "*.md"


def iter_target_files(target: Path):
    if target.is_file():
        yield target
    else:
        yield from sorted(target.rglob(FILE_GLOB))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--path",
        type=Path,
        default=DEFAULT_TARGET,
        help=f"File or directory to normalize (default: {DEFAULT_TARGET.relative_to(REPO_ROOT)})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without writing any files.",
    )
    args = parser.parse_args()

    target = args.path if args.path.is_absolute() else (REPO_ROOT / args.path)
    if not target.exists():
        print(f"ERROR: path not found: {target}", file=sys.stderr)
        return 2

    files_changed = 0
    total_replacements = 0

    for filepath in iter_target_files(target):
        try:
            original = filepath.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        normalized = normalize_repo_paths(original, REPO_ROOT)
        if normalized == original:
            continue
        # Count replacements as the drop in matched-prefix occurrences.
        removed = original.count("astred-bcdr-onboarding") - normalized.count("astred-bcdr-onboarding")
        files_changed += 1
        total_replacements += removed
        rel = filepath.relative_to(REPO_ROOT)
        print(f"  {'[dry-run] ' if args.dry_run else ''}{rel}: {removed} path(s)")
        if not args.dry_run:
            filepath.write_text(normalized, encoding="utf-8")

    verb = "Would normalize" if args.dry_run else "Normalized"
    print(f"\n{verb} {total_replacements} absolute path(s) across {files_changed} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
