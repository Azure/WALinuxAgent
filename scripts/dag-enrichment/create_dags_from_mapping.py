"""
Create intermediate and final DAG docs from a compose-to-DAG mapping file.

Supports both the 'symbols' and 'text' clustering approaches by accepting
the mapping file and output directories as parameters.

Usage:
    # Symbols approach
    python scripts/dag-enrichment/create_dags_from_mapping.py \
        --mapping scripts/dag-enrichment/compose_to_dag_mapping-symbols.json \
        --intermediate-dir scripts/dag-enrichment/output/clustering/symbols/intermediate-DAGs \
        --final-dir scripts/dag-enrichment/output/clustering/symbols/final-DAGs

    # Text approach
    python scripts/dag-enrichment/create_dags_from_mapping.py \
        --mapping scripts/dag-enrichment/compose_to_dag_mapping-text.json \
        --intermediate-dir scripts/dag-enrichment/output/clustering/text/intermediate-DAGs \
        --final-dir scripts/dag-enrichment/output/clustering/text/final-DAGs

    # Dry run (no agency copilot, just intermediate DAGs)
    python scripts/dag-enrichment/create_dags_from_mapping.py \
        --mapping <path> --intermediate-dir <path> --final-dir <path> --intermediate-only

    # Control parallelism for final DAG creation
    python scripts/dag-enrichment/create_dags_from_mapping.py \
        --mapping <path> --intermediate-dir <path> --final-dir <path> --max-parallel 6

Steps:
    1. Read mapping file (compose_to_dag_mapping-*.json)
    2. Extract ## Content from compose summaries → intermediate DAGs (grouped .content.md)
    3. Use agency copilot subagents to distill intermediate DAGs → final DAGs (~200 lines each)
"""

import json
import os
import re
import sys
import subprocess
import time
import fnmatch
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from dag_utils import detect_compose_base, normalize_repo_paths

MAX_LINES = 200

# Per-task hard timeout (seconds) for a single `agency copilot` step-4 subprocess.
# A wedged agency call otherwise hangs the whole step indefinitely (no non-zero exit,
# so the orchestrator's retry can't catch it). When a running task exceeds this, we
# kill it and mark it failed so the step can finish. Override via DAG_STEP4_TIMEOUT=0
# to disable, or any positive seconds value. Default 900s (15 min) — agency's own
# internal timeout is ~600s, so a healthy call never reaches this.
STEP4_TASK_TIMEOUT = int(os.environ.get("DAG_STEP4_TIMEOUT", "900"))

# Bounded per-doc retries before a final DAG doc is counted as permanently failed.
# Previously a failed agency call was counted but main() still exited 0, so the runner
# marked step 4 "complete" with L1/L2/L3 docs silently missing. Now each failed doc is
# re-queued up to DAG_LLM_RETRIES times; if it still fails, main() exits nonzero so the
# runner halts instead of shipping an incomplete doc set. Override via env.
DAG_LLM_RETRIES = int(os.environ.get("DAG_LLM_RETRIES", "3"))          # total attempts per doc
DAG_LLM_RETRY_BACKOFF = float(os.environ.get("DAG_LLM_RETRY_BACKOFF", "10"))  # base seconds before re-queue

# The `agency copilot` CLI prints this end-of-session footer once, at the very end,
# AFTER it has written + flushed the DAG doc. In practice the process sometimes then
# fails to exit (hangs holding a step-4 parallel slot). Detecting the footer lets us
# reap the finished call immediately instead of waiting out STEP4_TASK_TIMEOUT.
_AGENCY_DONE_RE = re.compile(r"copilot --resume=|^AI Credits\s", re.M)


def _agency_session_done(log_file: "Path | None") -> bool:
    """True once the agency CLI has printed its end-of-session footer (doc work done)."""
    if not log_file:
        return False
    try:
        with open(log_file, "rb") as fh:
            try:
                fh.seek(-4096, os.SEEK_END)
            except OSError:
                fh.seek(0)
            tail = fh.read().decode("utf-8", "replace")
    except OSError:
        return False
    return bool(_AGENCY_DONE_RE.search(tail))
MAX_PARALLEL = 4

# Source file extensions to include when creating intermediate DAGs
ALLOWED_SOURCE_EXTENSIONS = [
    ".cs.md",
    ".c.md",
    ".cc.md",
    ".cpp.md",
    ".h.md",
    ".hpp.md",
    ".py.md",
    ".rs.md",
]
MAX_FALLBACK_SYMBOL_CHARS = 1500
MAX_FALLBACK_SOURCE_CHARS = 2200


# ─── Helpers ────────────────────────────────────────────────────────────────

def extract_section(content: str, section: str) -> str:
    pattern = rf"^## {re.escape(section)}\s*\n(.*?)(?=^## |\Z)"
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    if match:
        text = match.group(1).strip()
        if text.startswith("````") and text.endswith("````"):
            text = text[4:-4].strip()
        elif text.startswith("```") and text.endswith("```"):
            text = text[3:-3].strip()
        return text
    return ""


def build_structural_fallback(summary: str, source_path: Path) -> str:
    """Build bounded LLM context when dry-run CCVG has no Content section."""
    symbols = extract_section(summary, "Symbols")[:MAX_FALLBACK_SYMBOL_CHARS]
    try:
        source = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        source = ""
    source = source[:MAX_FALLBACK_SOURCE_CHARS]

    sections = []
    if symbols:
        sections.append(f"### Structural symbols\n\n{symbols}")
    if source:
        sections.append(f"### Source excerpt\n\n````\n{source}\n````")
    return "\n\n".join(sections)


def extract_class_summaries(content: str) -> list[dict]:
    """Extract class-level summaries from compose output (--embed none format).

    Parses all '# Summary of <SymbolName>' sections after the file-level summary.
    Returns list of: {"symbol": "FQN", "short_name": "ClassName", "content": "..."}
    Returns empty list if no class-level summaries exist (--embed all format).
    """
    # Split on H1 headers: '# Summary of ...'
    parts = re.split(r'^# Summary of ', content, flags=re.MULTILINE)
    if len(parts) <= 2:
        # 0 or 1 splits = only file-level summary (or no summary at all)
        return []

    class_summaries = []
    # Skip parts[0] (before first header) and parts[1] (file-level summary)
    for part in parts[2:]:
        # Check if this is a Symbol (class) entry, not a File entry
        kind_match = re.search(r'^- Kind:\s*`(\w+)`', part, re.MULTILINE)
        if not kind_match or kind_match.group(1) == "File":
            continue

        # Extract the fully-qualified symbol name
        symbol_match = re.search(r'^- Symbol:\s*`([^`]+)`', part, re.MULTILINE)
        if not symbol_match:
            continue
        fqn = symbol_match.group(1)
        short_name = fqn.split(".")[-1]

        # Extract ## Content from this class section
        class_content = extract_section(part, "Content")
        if not class_content:
            continue

        class_summaries.append({
            "symbol": fqn,
            "short_name": short_name,
            "content": class_content,
        })

    return class_summaries


def get_relative_path(filepath: Path, compose_base: Path) -> str:
    try:
        return str(filepath.relative_to(compose_base)).replace("\\", "/")
    except ValueError:
        return str(filepath)


def should_ignore(rel_path: str, ignored_patterns: list) -> bool:
    for pattern in ignored_patterns:
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(os.path.basename(rel_path), pattern):
            return True
    return False


def is_cs_source(rel_path: str) -> bool:
    return any(rel_path.endswith(ext) for ext in ALLOWED_SOURCE_EXTENSIONS)


def matches_compose_dir(rel_path: str, compose_dir: str) -> bool:
    rel_norm = rel_path.replace("\\", "/")
    dir_norm = compose_dir.replace("\\", "/")
    if "." in os.path.basename(dir_norm):
        expected = dir_norm
        if not expected.endswith(".md"):
            expected += ".md"
        return rel_norm == expected or rel_norm.endswith("/" + expected)
    return rel_norm.startswith(dir_norm + "/") or rel_norm == dir_norm


def build_file_to_dag_map(mapping_data: dict):
    dir_map = {}
    file_map = {}
    for entry in mapping_data["mappings"]:
        dag_doc = entry.get("dag_doc") or entry.get("dag_doc_new")
        if not dag_doc:
            continue
        for cdir in entry.get("compose_dirs", []):
            dir_map[cdir.replace("\\", "/")] = dag_doc
        for cfile in entry.get("compose_files", []):
            file_map[cfile.replace("\\", "/")] = dag_doc
    return dir_map, file_map


def map_file_to_dag(rel_path: str, dir_map: dict, file_map: dict) -> str | None:
    rel_norm = rel_path.replace("\\", "/")
    if rel_norm in file_map:
        return file_map[rel_norm]
    best, best_len = None, 0
    for prefix, dag in dir_map.items():
        if matches_compose_dir(rel_path, prefix) and len(prefix) > best_len:
            best, best_len = dag, len(prefix)
    return best


# ─── Step 1: Create Intermediate DAGs ──────────────────────────────────────

def create_intermediate_dags(mapping_file: Path, output_dir: Path, compose_base: Path) -> dict:
    """Extract ## Content from compose summaries, group by DAG doc → intermediate .content.md"""
    print(f"\n{'='*60}")
    print("STEP 1: Creating Intermediate DAGs")
    print(f"{'='*60}")
    print(f"  Mapping:  {mapping_file}")
    print(f"  Compose:  {compose_base}")
    print(f"  Output:   {output_dir}")

    with open(mapping_file, "r", encoding="utf-8") as f:
        mapping_data = json.load(f)

    ignored_patterns = mapping_data.get("ignored_patterns", [])
    dir_map, file_map = build_file_to_dag_map(mapping_data)

    all_files = list(compose_base.rglob("*.md"))
    print(f"  Found {len(all_files)} compose summary files")

    dag_contents = defaultdict(list)
    unmapped, ignored, no_content, skipped = [], [], [], 0

    for filepath in sorted(all_files):
        rel_path = get_relative_path(filepath, compose_base)
        if should_ignore(rel_path, ignored_patterns):
            ignored.append(rel_path)
            continue
        if not is_cs_source(rel_path):
            skipped += 1
            continue
        try:
            text = filepath.read_text(encoding="utf-8")
        except Exception:
            continue
        source_file = rel_path[:-3] if rel_path.endswith(".md") else rel_path
        content = extract_section(text, "Content")
        if not content:
            content = build_structural_fallback(text, REPO_ROOT / source_file)
        if not content:
            no_content.append(rel_path)
            continue
        # Extract class-level summaries (--embed none format; empty for --embed all)
        class_summaries = extract_class_summaries(text)
        dag_doc = map_file_to_dag(rel_path, dir_map, file_map)
        if dag_doc:
            dag_contents[dag_doc].append((rel_path, content, class_summaries))
        else:
            unmapped.append(rel_path)

    # Write intermediate DAGs
    output_dir.mkdir(parents=True, exist_ok=True)
    for dag_doc, entries in sorted(dag_contents.items()):
        doc_output = output_dir / dag_doc.replace(".md", ".content.md")
        doc_output.parent.mkdir(parents=True, exist_ok=True)
        with open(doc_output, "w", encoding="utf-8") as f:
            f.write(f"# Compose Content for: {dag_doc}\n\n")
            f.write(f"Total files: {len(entries)}\n\n---\n\n")
            for rel_path, content, class_summaries in entries:
                f.write(f"## {source_file}\n\n{normalize_repo_paths(content, REPO_ROOT)}\n\n")
                # Append class-level summaries as H3 sub-sections (from --embed none)
                for cls in class_summaries:
                    cls_content = normalize_repo_paths(cls['content'], REPO_ROOT)
                    f.write(f"### Class: {cls['short_name']}\n\n{cls_content}\n\n")
                f.write("---\n\n")
        class_count = sum(len(cs) for _, _, cs in entries)
        class_info = f" (+{class_count} class summaries)" if class_count else ""
        print(f"    {dag_doc}: {len(entries)} files{class_info}")

    # Write unmapped report
    with open(output_dir / "_unmapped.txt", "w", encoding="utf-8") as f:
        f.write(f"Unmapped: {len(unmapped)}\n")
        for p in unmapped:
            f.write(f"  {p}\n")

    # Write coverage
    mapped_count = sum(len(v) for v in dag_contents.values())
    with open(output_dir / "_coverage.txt", "w", encoding="utf-8") as f:
        f.write(f"Total: {len(all_files)} | Mapped: {mapped_count} | "
                f"Ignored: {len(ignored)} | No Content: {len(no_content)} | "
                f"Skipped (non-.cs): {skipped} | Unmapped: {len(unmapped)}\n")

    print(f"\n  Mapped: {mapped_count} | Unmapped: {len(unmapped)} | "
          f"Intermediate DAGs: {len(dag_contents)}")
    return dag_contents


# ─── Step 2: Create Final DAGs via Agency Copilot ─────────────────────────

@dataclass
class EnrichTask:
    intermediate_file: Path
    final_doc: Path
    rel_path: str
    process: subprocess.Popen | None = None
    log_file: Path | None = None
    status: str = "pending"
    start_time: float = 0.0
    attempts: int = 0
    requeue_at: float = 0.0


def find_template(task_rel_path: str, template_final_dir: Path | None,
                   template_intermediate_dir: Path | None) -> tuple[Path | None, Path | None]:
    """Find matching or same-layer template from existing DAG dirs."""
    template_final = None
    template_intermediate = None

    if template_final_dir:
        # Try exact match first (same name in existing final DAGs)
        exact = template_final_dir / task_rel_path
        if exact.exists() and exact.stat().st_size > 100:
            template_final = exact
        else:
            # Fallback: any doc from the same layer (L1/L2/L3) as format reference
            layer = task_rel_path.split("/")[0]  # "L1-conceptual", "L2-platform", "L3-flows"
            layer_dir = template_final_dir / layer
            if layer_dir.exists():
                for md in sorted(layer_dir.glob("*.md")):
                    if md.name != "docs-index.md" and md.stat().st_size > 100:
                        template_final = md
                        break

    if template_intermediate_dir:
        # Try exact match in existing intermediate DAGs
        exact_name = task_rel_path.replace(".md", ".content.md")
        exact = template_intermediate_dir / exact_name
        if exact.exists() and exact.stat().st_size > 100:
            template_intermediate = exact

    return template_final, template_intermediate


def build_prompt(task: EnrichTask, final_dir: Path,
                 template_final: Path | None = None,
                 template_intermediate: Path | None = None) -> str:

    template_section = ""
    if template_final:
        template_section += f"""
TEMPLATE REFERENCE (existing final DAG doc — follow this format and style EXACTLY):
  {template_final}
  Read this file first to understand the expected structure: TL;DR, Why, What, How, Code Pointers table, Rules.
"""
    if template_intermediate:
        template_section += f"""
ADDITIONAL CONTEXT (existing intermediate DAG for the same topic from a prior run):
  {template_intermediate}
  This contains additional per-file summaries that may supplement the source content.
"""

    return f"""You are creating a DAG (Docs-Augmented Generation) document for an AI-native codebase.

TASK: Create a concise, agent-optimized DAG doc at:
  {task.final_doc}

SOURCE CONTENT (detailed per-file NL summaries):
  {task.intermediate_file}

Read the source content file completely. It contains per-file descriptions from compose summaries.
{template_section}
INSTRUCTIONS:
1. Read ALL content from the source file
2. {"Read the TEMPLATE REFERENCE file and match its structure exactly" if template_final else "Follow standard agentic doc structure"}
3. {"Read the ADDITIONAL CONTEXT file for supplementary details" if template_intermediate else ""}
4. Create the DAG doc at {task.final_doc}
5. Follow agentic doc principles:
   - TL;DR at the very top (1-2 sentences summarizing the component)
   - Why → What → How structure
   - Code pointers as Class/Method names (not embedded code)
   - HARD MAX {MAX_LINES} lines
   - Use tables for code pointer mappings
6. Synthesize — don't just concatenate file summaries
7. Include a Code Pointers table: Component | File Path | Key Classes
8. Add cross-references to related components if mentioned in the source

Write the file directly. Do not ask for confirmation."""


def create_final_dags(intermediate_dir: Path, final_dir: Path,
                       max_parallel: int, dry_run: bool = False,
                       template_final_dir: Path | None = None,
                       template_intermediate_dir: Path | None = None):
    """Distill intermediate DAGs into final ~200-line DAG docs via agency copilot."""
    print(f"\n{'='*60}")
    print("STEP 2: Creating Final DAGs via Agency Copilot")
    print(f"{'='*60}")
    print(f"  Intermediate: {intermediate_dir}")
    print(f"  Final:        {final_dir}")
    print(f"  Template final:        {template_final_dir or 'None'}")
    print(f"  Template intermediate:  {template_intermediate_dir or 'None'}")
    print(f"  Max parallel: {max_parallel}")
    print(f"  Dry run:      {dry_run}")

    log_dir = final_dir.parent / "enrichment-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    final_dir.mkdir(parents=True, exist_ok=True)

    # Build task list from intermediate DAGs
    tasks = []
    for cf in sorted(intermediate_dir.rglob("*.content.md")):
        if cf.name.startswith("_"):
            continue
        rel = str(cf.relative_to(intermediate_dir)).replace("\\", "/")
        dag_rel = rel.replace(".content.md", ".md")
        tasks.append(EnrichTask(
            intermediate_file=cf,
            final_doc=final_dir / dag_rel,
            rel_path=dag_rel,
        ))

    print(f"  Tasks: {len(tasks)}")

    if dry_run:
        for t in tasks:
            print(f"    [DRY-RUN] {t.rel_path}")
        print(f"\n  DRY RUN — {len(tasks)} final DAGs would be created")
        return 0

    # Run in batches
    pending = list(tasks)
    active = []
    completed = failed = 0

    def retry_or_fail(task: EnrichTask, reason: str) -> None:
        """Re-queue a failed doc with backoff, or count it permanently failed.

        Replaces the old behavior where a failed agency call was tallied but the
        step still exited 0 (runner saw green with docs missing). Now each doc gets
        up to DAG_LLM_RETRIES attempts; a doc that still fails is a permanent failure
        that makes main() exit nonzero so the runner halts.
        """
        nonlocal failed
        if task.attempts < DAG_LLM_RETRIES:
            wait = DAG_LLM_RETRY_BACKOFF * (2 ** (task.attempts - 1))
            task.status = "pending"
            task.process = None
            task.start_time = 0.0
            task.requeue_at = time.monotonic() + wait
            pending.append(task)
            print(f"    [retry] {task.rel_path}: {reason} — retry "
                  f"{task.attempts}/{DAG_LLM_RETRIES} in {wait:.0f}s")
        else:
            task.status = "failed"
            failed += 1
            print(f"    [X] {task.rel_path}: {reason} — giving up after "
                  f"{task.attempts} attempts")

    while pending or active:
        # Start new (skip tasks still in retry backoff via requeue_at)
        while len(active) < max_parallel:
            now = time.monotonic()
            idx = next((i for i, t in enumerate(pending) if t.requeue_at <= now), None)
            if idx is None:
                break
            task = pending.pop(idx)
            task.attempts += 1
            task.final_doc.parent.mkdir(parents=True, exist_ok=True)
            log_name = task.rel_path.replace("/", "_").replace("\\", "_").replace(".md", ".log")
            task.log_file = log_dir / log_name
            tf, ti = find_template(task.rel_path, template_final_dir, template_intermediate_dir)
            prompt = build_prompt(task, final_dir, template_final=tf, template_intermediate=ti)
            cmd = ["agency", "copilot", "-p", prompt, "--no-default-mcps"]
            with open(task.log_file, "w", encoding="utf-8") as lf:
                task.process = subprocess.Popen(
                    cmd, stdout=lf, stderr=subprocess.STDOUT,
                    cwd=str(REPO_ROOT), encoding="utf-8", errors="replace"
                )
            task.status = "running"
            task.start_time = time.monotonic()
            attempt_note = f" (attempt {task.attempts}/{DAG_LLM_RETRIES})" if task.attempts > 1 else ""
            print(f"    [CREATE] {task.rel_path} (PID {task.process.pid}){attempt_note}")
            active.append(task)

        # Poll
        time.sleep(10)
        still_active = []
        for task in active:
            rc = task.process.poll()
            if rc is None:
                # Agency may finish the doc + print its footer but never exit (hang);
                # reap it as soon as the footer appears so the slot frees immediately.
                if _agency_session_done(task.log_file):
                    hung_pid = task.process.pid
                    try:
                        task.process.kill()
                        task.process.wait(timeout=30)
                    except Exception:
                        pass
                    if task.final_doc.exists() and task.final_doc.stat().st_size > 0:
                        task.status = "completed"
                        completed += 1
                        lines = len(task.final_doc.read_text("utf-8").splitlines())
                        marker = "⚠" if lines > MAX_LINES else "✓"
                        print(f"    {marker} {task.rel_path}: {lines} lines "
                              f"(reaped hung agency PID {hung_pid})")
                    else:
                        retry_or_fail(task, f"agency footer but no doc (PID {hung_pid})")
                    continue
                elapsed = time.monotonic() - task.start_time
                if STEP4_TASK_TIMEOUT > 0 and elapsed > STEP4_TASK_TIMEOUT:
                    killed_pid = task.process.pid
                    try:
                        task.process.kill()
                        task.process.wait(timeout=30)
                    except Exception as e:
                        print(f"    ! kill error {task.rel_path}: {e}")
                    retry_or_fail(task, f"TIMEOUT after {elapsed:.0f}s "
                                        f"(> {STEP4_TASK_TIMEOUT}s), killed PID {killed_pid}")
                else:
                    still_active.append(task)
            elif rc == 0:
                if task.final_doc.exists() and task.final_doc.stat().st_size > 0:
                    task.status = "completed"
                    completed += 1
                    lines = len(task.final_doc.read_text("utf-8").splitlines())
                    marker = "⚠" if lines > MAX_LINES else "✓"
                    print(f"    {marker} {task.rel_path}: {lines} lines")
                else:
                    retry_or_fail(task, "exit 0 but no doc written")
            else:
                retry_or_fail(task, f"exit {rc}")
        active = still_active

        done = completed + failed
        total = len(tasks)
        pct = done / total * 100 if total else 0
        print(f"  Progress: {done}/{total} ({pct:.0f}%) | Running: {len(active)} | Pending: {len(pending)}")

    print(f"\n  COMPLETE: {completed} created | {failed} failed | {len(tasks)} total")
    if failed:
        print(f"  Logs: {log_dir}")
    return failed


# ─── Main ──────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Create intermediate and final DAGs from compose mapping")
    default_mapping = str(REPO_ROOT / "scripts" / "dag-enrichment" / "compose_to_dag_mapping-symbols.json")
    default_intermediate = str(REPO_ROOT / "intermediate-docs")
    default_final = str(REPO_ROOT / "copilot-docs")
    parser.add_argument("--mapping", default=default_mapping, help=f"Path to compose_to_dag_mapping-*.json (default: {default_mapping})")
    parser.add_argument("--intermediate-dir", default=default_intermediate, help=f"Output dir for intermediate DAGs (default: {default_intermediate})")
    parser.add_argument("--final-dir", default=default_final, help=f"Output dir for final DAGs (default: {default_final})")
    parser.add_argument("--compose-base", default=None, help="Path to compose summaries src directory (default: auto-detect)")
    parser.add_argument("--intermediate-only", action="store_true", help="Only create intermediate DAGs, skip agency copilot")
    parser.add_argument("--final-only", action="store_true", help="Skip intermediate creation, only run agency copilot on existing intermediates")
    parser.add_argument("--template-final-dir", default=None, help="Path to existing final DAGs to use as format templates (e.g. copilot-docs/)")
    parser.add_argument("--template-intermediate-dir", default=None, help="Path to existing intermediate DAGs for extra context (e.g. output/phase1/)")
    parser.add_argument("--max-parallel", type=int, default=MAX_PARALLEL, help=f"Max parallel agency copilot subagents (default: {MAX_PARALLEL})")
    parser.add_argument("--dry-run", action="store_true", help="Show plan without executing agency copilot")
    args = parser.parse_args()

    mapping_file = Path(args.mapping).resolve()
    intermediate_dir = Path(args.intermediate_dir).resolve()
    final_dir = Path(args.final_dir).resolve()
    compose_base = detect_compose_base(REPO_ROOT, args.compose_base)

    print("=" * 60)
    print("DAG CREATION FROM COMPOSE MAPPING")
    print("=" * 60)
    print(f"  Mapping:        {mapping_file}")
    print(f"  Intermediate:   {intermediate_dir}")
    print(f"  Final:          {final_dir}")
    print(f"  Approach:       {mapping_file.stem.replace('compose_to_dag_mapping-', '')}")

    if not args.final_only:
        create_intermediate_dags(mapping_file, intermediate_dir, compose_base)

    final_failed = 0
    if not args.intermediate_only:
        template_final = Path(args.template_final_dir).resolve() if args.template_final_dir else None
        template_intermediate = Path(args.template_intermediate_dir).resolve() if args.template_intermediate_dir else None
        final_failed = create_final_dags(intermediate_dir, final_dir, args.max_parallel, args.dry_run,
                          template_final_dir=template_final, template_intermediate_dir=template_intermediate)
    else:
        print(f"\n  --intermediate-only: Skipping final DAG creation")

    print(f"\n{'='*60}")
    print("DONE")
    print(f"{'='*60}")
    print(f"  Intermediate DAGs: {intermediate_dir}")
    print(f"  Final DAGs:        {final_dir}")

    # Fail loud: if any final DAG doc could not be produced after retries, exit
    # nonzero so the pipeline runner halts step 4 instead of marking it complete
    # with docs silently missing.
    if final_failed:
        print(f"\n  [X] {final_failed} final DAG doc(s) failed after retries — see logs above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
