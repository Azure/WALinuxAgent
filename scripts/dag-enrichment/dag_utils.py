"""
Shared utilities for the DAG enrichment pipeline.

Provides common helpers used across multiple pipeline scripts:
- detect_compose_base(): auto-detect compose summaries directory
- normalize_repo_paths(): strip machine-specific absolute path prefixes
"""

import re
from pathlib import Path


def normalize_repo_paths(text: str, repo_root: Path) -> str:
    """Rewrite machine-specific absolute paths that point inside the repo to
    repository-relative paths.

    Compose summaries embed the absolute on-disk path of each source file in
    their ``- Path:`` metadata (e.g.
    ``q:\\astred-bcdr-onboarding\\mgmt-recoverysvcs-wkloadextn\\src\\...``).
    Copying that verbatim into the generated docs leaks the author's local
    checkout location. This helper strips everything up to and including the
    repo root folder, leaving a stable relative path such as ``src\\...``.

    Matching is case-insensitive and tolerant of both ``\\`` and ``/`` separators
    so it works regardless of drive letter, casing, or checkout depth, as long
    as the repo folder name matches ``repo_root.name``.

    Args:
        text: The document text to sanitize.
        repo_root: Path to the repository root (its ``.name`` is the folder to strip).

    Returns:
        The text with absolute repo paths rewritten to repo-relative paths.
    """
    if not text:
        return text
    repo_name = repo_root.name
    # <drive>:<sep> ... <sep> <repo_name> <sep>  →  (removed, keep the remainder)
    # The non-greedy middle group consumes intermediate folders (e.g.
    # "astred-bcdr-onboarding\") without crossing a backtick delimiter.
    pattern = re.compile(
        r"[A-Za-z]:[\\/](?:[^\\/\n`]+[\\/])*?" + re.escape(repo_name) + r"[\\/]",
        re.IGNORECASE,
    )
    return pattern.sub("", text)


def detect_compose_base(repo_root: Path, override: str | None = None) -> Path:
    """Auto-detect the compose summaries base directory.

    Checks two locations in order:
      1. {repo_root}/.compose/summaries/src/  (--embed none output)
      2. {repo_root}/.astred/compose/summaries/{REPO_NAME}/src/  (--embed all output)

    Args:
        repo_root: Path to the repository root.
        override: If provided, use this path directly instead of auto-detecting.

    Returns:
        Path to the compose summaries src directory.
    """
    if override:
        return Path(override).resolve()
    # Check new path first: .compose/summaries/src/ (from --embed none)
    new_path = repo_root / ".compose" / "summaries" / "src"
    if new_path.exists():
        return new_path
    # Also check .compose/summaries/ for non-src layouts
    new_base = repo_root / ".compose" / "summaries"
    if new_base.exists():
        subdirs = [d for d in new_base.iterdir() if d.is_dir()]
        if subdirs:
            # If there's a src/ subdir, use it; otherwise use first subdir
            src_dir = new_base / "src"
            return src_dir if src_dir.exists() else subdirs[0]
    # Fall back to legacy path: .astred/compose/summaries/{REPO_NAME}/src/
    legacy_dir = repo_root / ".astred" / "compose" / "summaries"
    if legacy_dir.exists():
        subdirs = [d for d in legacy_dir.iterdir() if d.is_dir()]
        if len(subdirs) == 1:
            return subdirs[0] / "src"
        if len(subdirs) > 1:
            raise ValueError(
                f"Multiple summary dirs found: {[d.name for d in subdirs]}. "
                f"Use --compose-base to specify which one to use."
            )
    raise FileNotFoundError(
        f"No compose summaries found. Checked:\n"
        f"  {new_path}\n"
        f"  {legacy_dir}\n"
        f"Run astred compose first, or pass --compose-base <path>."
    )
