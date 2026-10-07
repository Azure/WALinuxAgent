"""
Incremental DAG Update Pipeline (Git-Diff Based)

Uses git diff to detect source code changes and propagate them into
intermediate → final DAGs without re-running astred compose.

Steps:
  A. Read .dag-state.json → old_hash, get HEAD → new_hash, git diff
  B. Map changed source files → affected DAGs via mapping JSON
  C. Update intermediate DAGs (LLM judges significance per file diff)
  D. Update final DAGs (full-resync or patch mode)
  E. Write new_hash to .dag-state.json

Usage:
    python scripts/dag-enrichment/update_dags.py --init          # one-time after initial DAGs
    python scripts/dag-enrichment/update_dags.py                 # incremental update
    python scripts/dag-enrichment/update_dags.py --mode patch    # cheaper LLM patch mode
    python scripts/dag-enrichment/update_dags.py --dry-run       # show plan without executing
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_MAPPING = REPO_ROOT / "scripts" / "dag-enrichment" / "compose_to_dag_mapping-symbols.json"
DEFAULT_INTERMEDIATE = REPO_ROOT / "intermediate-docs"
DEFAULT_FINAL = REPO_ROOT / "copilot-docs"
DEFAULT_STATE_FILE = REPO_ROOT / ".dag-state.json"
LOG_DIR = Path(__file__).resolve().parent / "output" / "update-logs"

SRC_PREFIX = "src/"
ALLOWED_EXTENSIONS = [".cs", ".c", ".cpp"]
IGNORED_PATTERNS = ["*/obj/*", "*/bin/*", "*/Properties/*"]
MAX_PARALLEL = 4


@dataclass
class FileDiff:
    source_path: str        # git path: src/Common/TokenManager/TokenManager.cs
    compose_key: str        # mapping key: Common/TokenManager/TokenManager.cs.md
    diff_text: str
    change_type: str        # modified | added | deleted | renamed


@dataclass
class AffectedDAG:
    dag_doc: str            # e.g. L2-platform/token-manager-framework.md
    layer: str              # L1-conceptual | L2-platform | L3-flows
    file_diffs: list        # list of FileDiff
    intermediate_path: Path
    final_path: Path
    intermediate_changed: bool = False
    intermediate_old_content: str = ""   # snapshot before Step C for diff computation


# ═══════════════════════════════════════════════════════════
# STATE MANAGEMENT
# ═══════════════════════════════════════════════════════════

def load_state(state_file: Path) -> dict:
    if not state_file.exists():
        return {}
    with open(state_file, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state_file: Path, state: dict):
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def init_state(state_file: Path, mapping_file: Path):
    """Initialize .dag-state.json with current HEAD."""
    head = get_git_head()
    state = {
        "last_updated_hash": head,
        "last_updated_timestamp": datetime.now(timezone.utc).isoformat(),
        "mapping_file": str(mapping_file.relative_to(REPO_ROOT)),
        "initial_hash": head,
        "update_count": 0,
    }
    save_state(state_file, state)
    print(f"Initialized .dag-state.json at {head[:12]}")
    return state


def get_git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True, text=True, cwd=str(REPO_ROOT)
    )
    return result.stdout.strip()


# ═══════════════════════════════════════════════════════════
# STEP A: GET GIT DIFF
# ═══════════════════════════════════════════════════════════

def get_changed_files(old_hash: str, new_hash: str, src_prefix: str) -> list[FileDiff]:
    """Get list of changed .cs files between two commits."""
    # Get changed file names with status
    result = subprocess.run(
        ["git", "diff", f"{old_hash}..{new_hash}", "--name-status", "--", f"{src_prefix}**/*.cs"],
        capture_output=True, text=True, cwd=str(REPO_ROOT)
    )
    if result.returncode != 0:
        # Try without globbing (some git versions don't support **)
        result = subprocess.run(
            ["git", "diff", f"{old_hash}..{new_hash}", "--name-status"],
            capture_output=True, text=True, cwd=str(REPO_ROOT)
        )

    diffs = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status = parts[0][0]  # M, A, D, R
        filepath = parts[-1]   # last part (handles renames)

        # Filter to source files only
        if not filepath.startswith(src_prefix):
            continue
        if not any(filepath.endswith(ext) for ext in ALLOWED_EXTENSIONS):
            continue
        if any(pat.replace("*", "") in filepath for pat in IGNORED_PATTERNS):
            continue

        change_type = {"M": "modified", "A": "added", "D": "deleted", "R": "renamed"}.get(status, "modified")

        # Get the actual diff text for this file
        diff_result = subprocess.run(
            ["git", "diff", f"{old_hash}..{new_hash}", "--", filepath],
            capture_output=True, text=True, cwd=str(REPO_ROOT)
        )
        diff_text = diff_result.stdout.strip()

        # Convert git path to mapping key
        # src/Common/TokenManager/TokenManager.cs → Common/TokenManager/TokenManager.cs.md
        rel_path = filepath[len(src_prefix):] if filepath.startswith(src_prefix) else filepath
        compose_key = rel_path + ".md"

        diffs.append(FileDiff(
            source_path=filepath,
            compose_key=compose_key,
            diff_text=diff_text,
            change_type=change_type,
        ))

    return diffs


# ═══════════════════════════════════════════════════════════
# STEP B: MAP FILES → DAGS
# ═══════════════════════════════════════════════════════════

def load_mapping(mapping_file: Path) -> dict:
    with open(mapping_file, "r", encoding="utf-8") as f:
        return json.load(f)


def build_reverse_index(mapping: dict) -> dict:
    """Build compose_file → dag_doc_new reverse index."""
    index = {}
    for entry in mapping.get("mappings", []):
        dag_doc = entry["dag_doc_new"]
        for cf in entry.get("compose_files", []):
            index[cf] = dag_doc
        # Also index by compose_dirs prefix
        for cd in entry.get("compose_dirs", []):
            index[f"__dir__{cd}"] = dag_doc
    return index


def map_file_to_dag(compose_key: str, reverse_index: dict) -> str | None:
    """Look up which DAG doc a compose file maps to."""
    # Exact match first
    if compose_key in reverse_index:
        return reverse_index[compose_key]
    # Dir prefix match
    parts = compose_key.split("/")
    for depth in range(len(parts) - 1, 0, -1):
        dir_prefix = "/".join(parts[:depth])
        if f"__dir__{dir_prefix}" in reverse_index:
            return reverse_index[f"__dir__{dir_prefix}"]
    return None


def group_diffs_by_dag(file_diffs: list[FileDiff], reverse_index: dict,
                       intermediate_dir: Path, final_dir: Path) -> dict[str, AffectedDAG]:
    """Group file diffs by their target DAG doc."""
    affected = {}
    unmapped = []

    for fd in file_diffs:
        dag_doc = map_file_to_dag(fd.compose_key, reverse_index)
        if dag_doc is None:
            unmapped.append(fd.source_path)
            continue

        if dag_doc not in affected:
            layer = dag_doc.split("/")[0]
            dag_name = dag_doc.split("/")[-1].replace(".md", "")
            affected[dag_doc] = AffectedDAG(
                dag_doc=dag_doc,
                layer=layer,
                file_diffs=[],
                intermediate_path=intermediate_dir / layer / f"{dag_name}.content.md",
                final_path=final_dir / dag_doc,
            )
        affected[dag_doc].file_diffs.append(fd)

    return affected, unmapped


# ═══════════════════════════════════════════════════════════
# STEP C: UPDATE INTERMEDIATE DAGS
# ═══════════════════════════════════════════════════════════

def extract_section(content: str, filename: str) -> tuple[str, int, int]:
    """Find a file's section in intermediate content. Returns (section_text, start_idx, end_idx)."""
    # Sections are delimited by "## <filename>" headers
    # e.g. "## Common/TokenManager/TokenManager.cs"
    pattern = rf"^## .*{re.escape(filename)}.*$"
    lines = content.split("\n")
    start = None
    end = None

    for i, line in enumerate(lines):
        if re.match(pattern, line, re.IGNORECASE):
            start = i
        elif start is not None and (line.startswith("## ") or line.startswith("---")):
            end = i
            break

    if start is None:
        return "", -1, -1
    if end is None:
        end = len(lines)

    return "\n".join(lines[start:end]), start, end


def update_intermediate_dag(dag: AffectedDAG, force: bool, dry_run: bool) -> bool:
    """Update an intermediate DAG based on file diffs. Returns True if changed."""
    if not dag.intermediate_path.exists():
        print(f"    WARNING: Intermediate not found: {dag.intermediate_path}")
        return False

    original_content = dag.intermediate_path.read_text(encoding="utf-8")
    dag.intermediate_old_content = original_content  # snapshot for diff in Step D
    updated_content = original_content
    changes_made = 0

    for fd in dag.file_diffs:
        # Extract the filename stem for section matching
        filename = fd.source_path.split("/")[-1]  # e.g. PluginConfigHelper.cs

        section, start, end = extract_section(updated_content, filename)
        if start == -1:
            print(f"    Section not found for {filename} in intermediate")
            continue

        if dry_run:
            diff_lines = len(fd.diff_text.split("\n"))
            print(f"    Would evaluate: {filename} ({fd.change_type}, {diff_lines} diff lines)")
            changes_made += 1
            continue

        # Call LLM to evaluate significance and get updated section
        updated_section = llm_evaluate_and_update(filename, section, fd.diff_text, force)

        if updated_section is None:
            print(f"    SKIP (trivial): {filename}")
            continue

        # Replace section in content
        lines = updated_content.split("\n")
        new_lines = lines[:start] + updated_section.split("\n") + lines[end:]
        updated_content = "\n".join(new_lines)
        changes_made += 1
        print(f"    UPDATED: {filename}")

    if changes_made > 0 and not dry_run:
        dag.intermediate_path.write_text(updated_content, encoding="utf-8")
        dag.intermediate_changed = True
    elif dry_run and changes_made > 0:
        dag.intermediate_changed = True

    return changes_made > 0


def llm_evaluate_and_update(filename: str, current_section: str, diff_text: str, force: bool) -> str | None:
    """Call LLM to evaluate diff significance and produce targeted edits.
    Returns updated section text, or None if change is trivial."""

    prompt = f"""You are updating an existing documentation section for a source code file that has changed.

## EXISTING summary section for {filename} (DO NOT SHORTEN OR REMOVE CONTENT):
---
{current_section}
---

## Git diff for this file:
---
{diff_text[:8000]}
---

## CRITICAL RULES:
1. First, assess significance:
   - Trivial (respond "NO_UPDATE" for ANY of these):
     * Whitespace, formatting, or indentation changes
     * Comment-only changes (added/removed/edited comments)
     * Import/using statement reordering
     * Version bumps in constants without behavioral change
     * Pure refactoring with NO logical change (e.g., if-else → switch-case, extract method,
       inline variable, rename local variable, consolidate duplicate code into helper)
     * Moving code between regions without changing behavior
   - Significant (continue to step 2):
     * New methods, classes, or properties added
     * Method signatures changed (new parameters, different return types)
     * Control flow logic changed (new branches, different conditions, new error handling)
     * Bug fixes that change runtime behavior
     * New configuration options or feature flags
     * Security-related changes (encryption, auth, certificates)

2. If significant, produce the COMPLETE updated section following these STRICT rules:
   - START with the EXACT same "## <filepath>" header as the existing section
   - PRESERVE ALL existing content that is still accurate after the code change
   - ADD new bullet points or sentences describing the new/changed functionality
   - MODIFY only the specific sentences that are directly contradicted by the diff
   - REMOVE content ONLY if the diff shows that specific functionality was deleted from the code
   - DO NOT summarize, shorten, or rephrase existing content that is unaffected by the diff
   - DO NOT drop subsections like "Interactions and Dependencies", "Key Components", "Conclusion"
   - The section may contain ### Class: subsections with per-class detail.
     Preserve these subsections. If the diff adds a new class, add a new ### Class: subsection.
     If a class is deleted, remove its subsection.

3. If trivial, respond with exactly "NO_UPDATE" (nothing else).

{"IMPORTANT: Treat ALL changes as significant (--force mode)." if force else ""}
"""

    prompt_file = LOG_DIR / f"_update_prompt_{filename}.txt"
    result_file = LOG_DIR / f"_update_result_{filename}.txt"

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    prompt_file.write_text(prompt, encoding="utf-8")

    if result_file.exists():
        result_file.unlink()

    cmd = [
        "agency", "copilot",
        "-p", f"Read {prompt_file.resolve()} and follow instructions. Write output to {result_file.resolve()}. No markdown fences.",
        "--no-default-mcps"
    ]

    try:
        subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True,
                       encoding="utf-8", errors="replace", timeout=120)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"    LLM call failed for {filename}: {e}")
        return None

    if result_file.exists():
        result = result_file.read_text(encoding="utf-8").strip()
        if result == "NO_UPDATE" or result.startswith("NO_UPDATE"):
            return None
        # Guard: reject results that lost significant content
        original_lines = len(current_section.strip().splitlines())
        result_lines = len(result.strip().splitlines())
        if result_lines < original_lines * 0.8:
            print(f"    REJECTED (content loss): {filename} — "
                  f"original {original_lines} lines → LLM returned {result_lines} lines "
                  f"({result_lines - original_lines:+d}). Keeping original.")
            return None
        return result

    return None


# ═══════════════════════════════════════════════════════════
# STEP D: UPDATE FINAL DAGS
# ═══════════════════════════════════════════════════════════

def compute_intermediate_diff(dag: AffectedDAG) -> str:
    """Compute a readable diff between old and new intermediate content."""
    if not dag.intermediate_old_content or not dag.intermediate_path.exists():
        return ""
    new_content = dag.intermediate_path.read_text(encoding="utf-8")
    if dag.intermediate_old_content == new_content:
        return ""

    # Build a section-level diff showing what changed
    old_lines = dag.intermediate_old_content.split("\n")
    new_lines = new_content.split("\n")

    import difflib
    diff = difflib.unified_diff(old_lines, new_lines, lineterm="",
                                 fromfile="old-intermediate", tofile="new-intermediate", n=3)
    return "\n".join(list(diff)[:500])  # cap at 500 lines to stay within LLM context


def call_copilot_cli(prompt: str, result_file: Path, timeout: int = 300) -> str | None:
    """Call GitHub Copilot CLI and read the result from file.
    Returns the result text, or None if failed."""
    prompt_file = result_file.with_suffix(".prompt.txt")
    prompt_file.parent.mkdir(parents=True, exist_ok=True)
    prompt_file.write_text(prompt, encoding="utf-8")

    if result_file.exists():
        result_file.unlink()

    cmd = [
        "agency", "copilot",
        "-p", f"Read {prompt_file.resolve()} and follow its instructions exactly. "
              f"Write ONLY the output to {result_file.resolve()}. No markdown fences.",
        "--no-default-mcps"
    ]

    try:
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"    LLM call failed: {e}")
        return None

    if result_file.exists():
        return result_file.read_text(encoding="utf-8").strip()
    return None


def update_final_dag_resync(dag: AffectedDAG, dry_run: bool) -> bool:
    """Full re-synthesis of final DAG from intermediate."""
    if dry_run:
        print(f"    Would re-synthesize: {dag.final_path.name}")
        return True

    intermediate_content = dag.intermediate_path.read_text(encoding="utf-8")

    prompt = f"""You are synthesizing a final DAG documentation file from intermediate source summaries.

Read the content below and synthesize it into a documentation file (~200 lines max).
Structure: Title → TL;DR → Why → What → How → Code Pointers table.
Do NOT simply concatenate — synthesize, deduplicate, and organize.
No markdown fences around the output. Write the COMPLETE document.

## Intermediate content:
---
{intermediate_content}
---"""

    result_file = LOG_DIR / f"_final_result_{dag.final_path.stem}.txt"
    result = call_copilot_cli(prompt, result_file)

    if result and len(result) > 50:
        dag.final_path.parent.mkdir(parents=True, exist_ok=True)
        dag.final_path.write_text(result, encoding="utf-8")
        print(f"    WRITTEN: {dag.final_path.name} ({len(result.splitlines())} lines)")
        return True
    else:
        print(f"    FAILED: No output or too short for {dag.final_path.name}")
        return False


def update_final_dag_patch(dag: AffectedDAG, intermediate_diff: str, dry_run: bool) -> bool:
    """Patch final DAG using intermediate diff."""
    if dry_run:
        print(f"    Would patch: {dag.final_path.name}")
        return True

    if not dag.final_path.exists():
        print(f"    Final DAG not found, falling back to full resync: {dag.final_path}")
        return update_final_dag_resync(dag, dry_run)

    if not intermediate_diff or intermediate_diff.strip() == "":
        print(f"    SKIP: No intermediate diff for {dag.final_path.name}")
        return False

    current_final = dag.final_path.read_text(encoding="utf-8")

    prompt = f"""You are updating an existing DAG documentation file based on changes to its source material.

## Current Final DAG (PRESERVE ALL OF THIS — only modify sections affected by the diff):
---
{current_final}
---

## Diff of intermediate changes (unified diff format):
---
{intermediate_diff}
---

## CRITICAL RULES:
- PRESERVE the existing structure: Title, TL;DR, Why, What, How, Code Pointers, Tests
- PRESERVE ALL existing content that is unaffected by the diff — do NOT summarize, shorten, or drop it
- MODIFY only the specific sentences/bullets where the diff shows changed functionality
- ADD new content where the diff introduces new functionality
- REMOVE content ONLY if the diff shows that specific functionality was deleted
- DO NOT drop the "How", "Code Pointers", or "Tests" sections even if they are unaffected
- Keep under 200 lines
- Write the COMPLETE updated document (every section, not just the changed parts)"""

    result_file = LOG_DIR / f"_patch_result_{dag.final_path.stem}.txt"
    result = call_copilot_cli(prompt, result_file)

    if result and len(result) > 50:
        # Guard: reject results that lost significant content
        original_lines = len(current_final.strip().splitlines())
        result_lines = len(result.strip().splitlines())
        if result_lines < original_lines * 0.75:
            print(f"    REJECTED (content loss): {dag.final_path.name} — "
                  f"original {original_lines} lines → LLM returned {result_lines} lines "
                  f"({result_lines - original_lines:+d}). Keeping original.")
            return False
        dag.final_path.write_text(result, encoding="utf-8")
        print(f"    PATCHED: {dag.final_path.name} ({len(result.splitlines())} lines)")
        return True
    else:
        print(f"    FAILED: Patch output missing or too short for {dag.final_path.name}")
        return False


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Incremental DAG Update Pipeline (Git-Diff Based)")
    parser.add_argument("--init", action="store_true",
                        help="Initialize .dag-state.json with current HEAD. Run once after initial DAG creation.")
    parser.add_argument("--mode", choices=["full-resync", "patch"], default="full-resync",
                        help="Update mode: full-resync (re-synthesize) or patch (diff-based). Default: full-resync")
    parser.add_argument("--mapping", default=str(DEFAULT_MAPPING),
                        help=f"Path to mapping JSON. Default: {DEFAULT_MAPPING.relative_to(REPO_ROOT)}")
    parser.add_argument("--intermediate-dir", default=str(DEFAULT_INTERMEDIATE),
                        help=f"Intermediate DAGs directory. Default: {DEFAULT_INTERMEDIATE.relative_to(REPO_ROOT)}")
    parser.add_argument("--final-dir", default=str(DEFAULT_FINAL),
                        help=f"Final DAGs directory. Default: {DEFAULT_FINAL.relative_to(REPO_ROOT)}")
    parser.add_argument("--state-file", default=str(DEFAULT_STATE_FILE),
                        help=f"State file path. Default: {DEFAULT_STATE_FILE.relative_to(REPO_ROOT)}")
    parser.add_argument("--max-parallel", type=int, default=MAX_PARALLEL,
                        help=f"Max parallel LLM calls. Default: {MAX_PARALLEL}")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show affected DAGs and diffs without updating.")
    parser.add_argument("--force", action="store_true",
                        help="Skip significance check, update all affected DAGs.")
    parser.add_argument("--to-hash", default=None,
                        help="Target git commit hash. Default: HEAD")
    parser.add_argument("--src-prefix", default=SRC_PREFIX,
                        help=f"Source directory prefix to strip. Default: {SRC_PREFIX}")
    args = parser.parse_args()

    mapping_file = Path(args.mapping).resolve()
    intermediate_dir = Path(args.intermediate_dir).resolve()
    final_dir = Path(args.final_dir).resolve()
    state_file = Path(args.state_file).resolve()

    print("=" * 60)
    print("INCREMENTAL DAG UPDATE PIPELINE")
    print("=" * 60)

    # ── Init mode ──
    if args.init:
        init_state(state_file, mapping_file)
        return

    # ── Load state ──
    state = load_state(state_file)
    if not state or "last_updated_hash" not in state:
        print("ERROR: .dag-state.json not found or invalid. Run with --init first.")
        sys.exit(1)

    old_hash = state["last_updated_hash"]
    new_hash = args.to_hash or get_git_head()

    if old_hash == new_hash:
        print(f"DAGs already at {new_hash[:12]}. Nothing to do.")
        return

    print(f"  Mode:          {args.mode}")
    print(f"  Mapping:       {mapping_file.name}")
    print(f"  Intermediate:  {intermediate_dir}")
    print(f"  Final:         {final_dir}")
    print(f"  Old hash:      {old_hash[:12]}")
    print(f"  New hash:      {new_hash[:12]}")
    print(f"  Dry run:       {args.dry_run}")
    print(f"  Force:         {args.force}")

    # ── Step A: Get git diff ──
    print(f"\n{'─' * 60}")
    print("STEP A: Detecting changed source files...")
    print(f"{'─' * 60}")

    file_diffs = get_changed_files(old_hash, new_hash, args.src_prefix)
    print(f"  Found {len(file_diffs)} changed source files")

    if not file_diffs:
        print("  No source file changes detected. Nothing to update.")
        if not args.dry_run:
            state["last_updated_hash"] = new_hash
            state["last_updated_timestamp"] = datetime.now(timezone.utc).isoformat()
            save_state(state_file, state)
            print(f"  Updated state to {new_hash[:12]} (no DAG changes needed)")
        return

    for fd in file_diffs:
        print(f"    {fd.change_type:>8}: {fd.source_path}")

    # ── Step B: Map to DAGs ──
    print(f"\n{'─' * 60}")
    print("STEP B: Mapping changed files to DAGs...")
    print(f"{'─' * 60}")

    mapping = load_mapping(mapping_file)
    reverse_index = build_reverse_index(mapping)
    affected_dags, unmapped = group_diffs_by_dag(file_diffs, reverse_index, intermediate_dir, final_dir)

    print(f"  Affected DAGs: {len(affected_dags)}")
    for dag_doc, dag in sorted(affected_dags.items()):
        print(f"    {dag_doc} ({len(dag.file_diffs)} files changed)")
        for fd in dag.file_diffs:
            print(f"      {fd.change_type}: {fd.source_path.split('/')[-1]}")

    if unmapped:
        print(f"\n  Unmapped files ({len(unmapped)}) — need full pipeline:")
        for path in unmapped:
            print(f"    {path}")

    # ── Step C: Update intermediates ──
    print(f"\n{'─' * 60}")
    print("STEP C: Updating intermediate DAGs...")
    print(f"{'─' * 60}")

    intermediates_updated = 0
    for dag_doc, dag in sorted(affected_dags.items()):
        print(f"\n  [{dag_doc}]")
        if not dag.intermediate_path.exists():
            print(f"    SKIP: intermediate not found at {dag.intermediate_path}")
            continue
        changed = update_intermediate_dag(dag, args.force, args.dry_run)
        if changed:
            intermediates_updated += 1

    print(f"\n  Intermediates {'would be ' if args.dry_run else ''}updated: {intermediates_updated}/{len(affected_dags)}")

    # ── Step D: Update finals (parallel — each final DAG is independent) ──
    dags_to_update_final = [d for d in affected_dags.values() if d.intermediate_changed]

    if not dags_to_update_final:
        print(f"\n{'─' * 60}")
        print("STEP D: No intermediate changes → skipping final DAG updates")
        print(f"{'─' * 60}")
    else:
        print(f"\n{'─' * 60}")
        print(f"STEP D: Updating {len(dags_to_update_final)} final DAGs ({args.mode}, max-parallel={args.max_parallel})...")
        print(f"{'─' * 60}")

        # Pre-compute intermediate diffs before parallel execution (reads old_content which is in-memory)
        dag_diffs = {}
        if args.mode == "patch":
            for dag in dags_to_update_final:
                dag_diffs[dag.dag_doc] = compute_intermediate_diff(dag)

        def update_one_final(dag: AffectedDAG) -> tuple[str, bool]:
            """Update a single final DAG. Returns (dag_doc, success)."""
            if args.mode == "full-resync":
                ok = update_final_dag_resync(dag, args.dry_run)
            else:
                ok = update_final_dag_patch(dag, dag_diffs.get(dag.dag_doc, ""), args.dry_run)
            return dag.dag_doc, ok

        from concurrent.futures import ThreadPoolExecutor, as_completed

        finals_updated = 0
        with ThreadPoolExecutor(max_workers=args.max_parallel) as pool:
            futures = {pool.submit(update_one_final, dag): dag for dag in dags_to_update_final}
            for future in as_completed(futures):
                dag_doc, ok = future.result()
                print(f"  [{dag_doc}] {'✓' if ok else '✗'}")
                if ok:
                    finals_updated += 1

        print(f"\n  Finals {'would be ' if args.dry_run else ''}updated: {finals_updated}/{len(dags_to_update_final)}")

    # ── Step E: Update state ──
    if not args.dry_run:
        print(f"\n{'─' * 60}")
        print("STEP E: Updating state...")
        print(f"{'─' * 60}")

        state["last_updated_hash"] = new_hash
        state["last_updated_timestamp"] = datetime.now(timezone.utc).isoformat()
        state["update_count"] = state.get("update_count", 0) + 1
        save_state(state_file, state)
        print(f"  State updated to {new_hash[:12]} (update #{state['update_count']})")

        # Append to update log
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_entry = {
            "timestamp": state["last_updated_timestamp"],
            "old_hash": old_hash,
            "new_hash": new_hash,
            "mode": args.mode,
            "changed_source_files": len(file_diffs),
            "affected_dags": len(affected_dags),
            "intermediates_updated": intermediates_updated,
            "unmapped_files": len(unmapped),
        }
        log_file = LOG_DIR / "update_log.json"
        logs = []
        if log_file.exists():
            logs = json.loads(log_file.read_text(encoding="utf-8"))
        logs.append(log_entry)
        log_file.write_text(json.dumps(logs, indent=2), encoding="utf-8")
        print(f"  Log appended to {log_file.relative_to(REPO_ROOT)}")
    else:
        print(f"\n{'─' * 60}")
        print("DRY RUN COMPLETE — no changes made")
        print(f"{'─' * 60}")

    # ── Summary ──
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Changed files:       {len(file_diffs)}")
    print(f"  Affected DAGs:       {len(affected_dags)}")
    print(f"  Intermediates updated: {intermediates_updated}")
    print(f"  Finals updated:      {len(dags_to_update_final)}")
    print(f"  Unmapped files:      {len(unmapped)}")
    print(f"  Hash range:          {old_hash[:12]}..{new_hash[:12]}")


if __name__ == "__main__":
    main()
