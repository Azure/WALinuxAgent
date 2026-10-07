"""
Step 2: Label clusters using LLM in batched calls with rich context.

Improvements over v1 (single massive LLM call):
  1. BATCHED: Processes ~15 clusters per LLM call instead of all 174 at once
  2. RICHER PROMPT: Defines L1/L2/L3 with concrete codebase examples and anti-patterns
  3. NAMING GUIDANCE: Instructs LLM to name by core concept, not file/directory names
  4. DEDUP PASS: Post-processing validates uniqueness and fixes near-duplicates via LLM
  5. LAYER VALIDATION: Validates layer assignments with codebase-specific rules

Supports two approaches:
  --approach text     (default) Read from clustering/text/
  --approach symbols  Read from clustering/symbols/

Usage:
    python scripts/dag-enrichment/step2_label_clusters.py [--approach text|symbols]

Output:
    scripts/dag-enrichment/output/clustering/{text|symbols}/cluster_labels.json
"""

import json
import os
import re
import sys
import subprocess
import time
from pathlib import Path
from collections import Counter, defaultdict
from difflib import SequenceMatcher

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CLUSTERING_BASE = Path(__file__).resolve().parent / "output" / "clustering"
MODELS_FILE = REPO_ROOT / ".compose.models.json"

DEFAULT_BATCH_SIZE = 15  # clusters per LLM call

# Bounded retries for a failed label batch before failing loud. Removing the old
# silent fallback (which hard-coded layer="L2-platform" for every cluster in a
# failed batch) — that fabrication was the root cause of missing L1/L3 tiers.
# On persistent failure we abort the whole labeling step (sys.exit) rather than
# write a partial / fabricated mapping. Override via env.
DAG_LLM_RETRIES = int(os.environ.get("DAG_LLM_RETRIES", "3"))          # total attempts per batch
DAG_LLM_RETRY_BACKOFF = float(os.environ.get("DAG_LLM_RETRY_BACKOFF", "10"))  # base seconds (10/20/40)


def get_approach():
    approach = "symbols"
    for i, arg in enumerate(sys.argv):
        if arg == "--approach" and i + 1 < len(sys.argv):
            approach = sys.argv[i + 1]
    if approach not in ("text", "symbols"):
        print(f"ERROR: Unknown approach '{approach}'. Use 'text' or 'symbols'.")
        sys.exit(1)
    return approach


def load_cluster_data(output_dir: Path):
    with open(output_dir / "cluster_assignments.json", "r") as f:
        assignments = json.load(f)
    with open(output_dir / "file_metadata.json", "r") as f:
        metadata = json.load(f)
    # Load cluster details for defining namespace info (symbols approach)
    details = {}
    details_file = output_dir / "cluster_details.json"
    if details_file.exists():
        with open(details_file, "r") as f:
            details = json.load(f)
    with open(output_dir / "elbow_results.json", "r") as f:
        elbow = json.load(f)
    return assignments, metadata, details, elbow["optimal_k"]


def build_cluster_summaries(assignments, metadata, details, k):
    """Build a rich summary of each cluster for LLM labeling."""
    clusters = {i: [] for i in range(k)}
    for file_path, cluster_id in assignments.items():
        clusters[cluster_id].append(file_path)

    summaries = {}
    for cid in range(k):
        files = clusters[cid]
        if not files:
            continue

        dirs = Counter()
        all_symbols = []
        content_previews = []

        for fp in files:
            meta = metadata.get(fp, {})
            dir_path = "/".join(fp.split("/")[:-1])
            dirs[dir_path] += 1
            all_symbols.extend(meta.get("symbols", []))
            if meta.get("content_preview"):
                content_previews.append(meta["content_preview"][:200])

        top_dirs = [d for d, _ in dirs.most_common(5)]

        # Top namespaces (deduplicated at depth 4)
        ns_counter = Counter()
        for sym in all_symbols:
            parts = sym.split(".")
            if len(parts) >= 4:
                ns = ".".join(parts[:4])
                ns_counter[ns] += 1
            elif len(parts) >= 2:
                ns_counter[".".join(parts[:2])] += 1
        top_namespaces = [ns for ns, _ in ns_counter.most_common(5)]

        sample_names = [fp.split("/")[-1].replace(".cs.md", "") for fp in files[:15]]

        # Get defining namespace from cluster details (symbols approach)
        defining_ns = ""
        cid_str = str(cid)
        if cid_str in details:
            defining_ns = details[cid_str].get("defining_ns", "")

        # Determine if mostly test files
        test_kw = ["test", "tests", "bvt", "mock", "cvt"]
        test_ratio = sum(1 for f in files if any(k in f.lower() for k in test_kw)) / max(len(files), 1)

        # Key classes (non-test, non-constant, non-interface prefix)
        key_classes = [n for n in sample_names if not any(n.lower().startswith(k) for k in ["test", "mock", "i"])
                       and n not in ("Constants", "Program", "AssemblyInfo")][:8]

        summaries[cid] = {
            "file_count": len(files),
            "files": files,
            "sample_names": sample_names,
            "key_classes": key_classes,
            "top_dirs": top_dirs,
            "top_namespaces": top_namespaces,
            "content_previews": content_previews[:3],
            "defining_ns": defining_ns,
            "test_ratio": round(test_ratio, 2),
        }

    return summaries


# ═══════════════════════════════════════════════════════════
# SYSTEM PROMPT — shared across all batches
# ═══════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are an expert at labeling code clusters for documentation generation.

## Your Task
For each cluster, you must provide:
1. **filename**: A kebab-case filename (no .md extension) that captures the CORE CONCEPT of the cluster
2. **description**: A ONE-LINE description (max 120 chars) of what this cluster does
3. **layer**: One of L1-conceptual, L2-platform, or L3-flows

## NAMING RULES (Critical)
- Name by the CORE CONCEPT the cluster represents, NOT by directory or namespace names
- Good: "auth-token-management", "data-pipeline-core", "api-request-handler", "config-store"
- Bad: "common-utils-common", "src-services-internal", "microsoft-internal-foo"
- Keep filenames 2-5 words in kebab-case, max 40 characters
- Names must be UNIQUE and DISTINGUISHABLE from other clusters
- If a cluster is about tests, include the subsystem being tested: "auth-unit-tests" not just "tests"
- Do NOT repeat parent namespace segments — "handler-config" not "handler-handler-config"

## LAYER CLASSIFICATION (Critical)

### L1-conceptual — "What is it?" — Architecture & Contracts
Core frameworks, abstract patterns, interfaces, and architectural building blocks that define the system's design.
ASSIGN L1 WHEN: The cluster defines interfaces, abstract base classes, factory patterns, service contracts,
or core engine implementations that other parts of the system depend on.
EXAMPLES:
- Core engine or runtime (state machines, schedulers, dispatchers)
- Service contracts and interface definitions
- Plugin/extension/adapter abstractions
- Data model and domain entity definitions
- Architectural patterns (pipeline, mediator, repository)

### L2-platform — "How does it work?" — Infrastructure & Services
Concrete implementation of platform services, utilities, cross-cutting infrastructure, configuration,
diagnostics, encryption, scheduling, health monitoring, telemetry, AND ALL TEST CODE.
ASSIGN L2 WHEN: The cluster implements platform utilities, configuration management, health/diagnostics,
tools, OR contains test/mock/BVT code.
EXAMPLES:
- Authentication, token management, encryption
- Configuration stores and settings management
- Logging, tracing, telemetry, health checks
- HTTP clients, serialization, caching utilities
- Build tools, code generators, CLI helpers
- All unit tests, integration tests, mock libraries, test infrastructure

### L3-flows — "How to do it?" — End-to-End Workflows
Complete operational workflows, request processing pipelines, and orchestration sequences.
ASSIGN L3 WHEN: The cluster contains end-to-end workflow implementations, request handlers that
compose multiple services, or operational flow orchestration.
EXAMPLES:
- Request processing pipelines (receive → validate → execute → respond)
- Multi-step workflows and orchestration
- Feature-specific operation implementations (CRUD flows, data sync, import/export)
- Integration flows connecting external systems
- Scheduled job implementations and batch processing

### LAYER ANTI-PATTERNS (avoid these mistakes)
- Concrete feature implementations with workflow logic -> L3, not L1
- Test files -> ALWAYS L2, never L1 or L3
- Workflow orchestration steps -> L3, not L2
- Abstract base classes and interfaces that define contracts -> L1
- Broad utility/common namespaces with no clear architecture role -> L2

## OUTPUT FORMAT
Return ONLY a JSON array. Each element:
{"cluster_id": 0, "filename": "core-engine", "description": "Core engine with scheduling and dispatch", "layer": "L1-conceptual"}

No markdown fences. No explanation. ONLY the JSON array."""


def build_batch_prompt(batch_summaries: dict, batch_idx: int, total_batches: int, used_names: list) -> str:
    """Build a prompt for one batch of clusters."""
    cluster_lines = []
    for cid in sorted(batch_summaries.keys()):
        info = batch_summaries[cid]
        lines = [f"Cluster {cid} ({info['file_count']} files):"]
        if info["defining_ns"]:
            lines.append(f"  Defining namespace: {info['defining_ns']}")
        lines.append(f"  Directories: {', '.join(info['top_dirs'][:4])}")
        lines.append(f"  Key namespaces: {', '.join(info['top_namespaces'][:4])}")
        lines.append(f"  Key classes: {', '.join(info['key_classes'][:8])}")
        lines.append(f"  All files: {', '.join(info['sample_names'][:12])}")
        if info["test_ratio"] > 0.5:
            lines.append(f"  NOTE: Test-heavy cluster ({info['test_ratio']:.0%} test files) -> must be L2-platform")
        if info["content_previews"]:
            lines.append(f"  Content: {info['content_previews'][0][:150]}")
        cluster_lines.append("\n".join(lines))

    clusters_text = "\n\n".join(cluster_lines)

    # Include already-used names so the LLM avoids duplicates
    used_names_str = ""
    if used_names:
        used_names_str = f"\n\n## ALREADY USED FILENAMES (do NOT reuse these):\n{', '.join(used_names)}\n"

    return f"""Batch {batch_idx + 1}/{total_batches} — Label the following {len(batch_summaries)} clusters.
{used_names_str}
{clusters_text}

Return ONLY a JSON array with {len(batch_summaries)} elements. Each must have: cluster_id, filename, description, layer."""


def call_llm_batch(prompt: str, system_prompt: str, output_dir: Path, batch_idx: int) -> list | None:
    """Call LLM for a single batch."""
    prompt_file = output_dir / f"_label_prompt_batch{batch_idx}.txt"
    result_file = output_dir / f"_label_result_batch{batch_idx}.txt"

    full_prompt = f"{system_prompt}\n\n---\n\n{prompt}"
    prompt_file.write_text(full_prompt, encoding="utf-8")

    # Clean up old result
    if result_file.exists():
        result_file.unlink()

    cmd = [
        "agency", "copilot",
        "-p", f"Read the file {prompt_file.resolve()} and follow its instructions exactly. Write ONLY the JSON array output to {result_file.resolve()}. No markdown fences.",
        "--no-default-mcps"
    ]

    try:
        proc = subprocess.run(
            cmd, cwd=str(REPO_ROOT),
            capture_output=True, encoding="utf-8", errors="replace", timeout=300
        )
    except subprocess.TimeoutExpired:
        print(f"    Batch {batch_idx}: TIMEOUT")
        return None

    # Read result file
    if result_file.exists():
        raw = result_file.read_text(encoding="utf-8").strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1]
            raw = raw.rsplit("```", 1)[0].strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # Try extracting JSON array from the text
            match = re.search(r'\[[\s\S]*\]', raw)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass
            print(f"    Batch {batch_idx}: Failed to parse JSON from result file")
            print(f"    First 300 chars: {raw[:300]}")

    # Try stdout
    stdout = proc.stdout or ""
    match = re.search(r'\[[\s\S]*?\]', stdout)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    return None


def validate_and_fix_names(all_labels: list, cluster_summaries: dict, output_dir: Path) -> list:
    """Post-processing: fix near-duplicate names and layer violations."""
    # Pass 1: Ensure unique filenames
    seen_names = {}
    for entry in all_labels:
        fn = entry["filename"]
        if fn in seen_names:
            old = fn
            ns = cluster_summaries.get(entry["cluster_id"], {}).get("defining_ns", "")
            suffix = ns.split(".")[-1].lower() if ns else str(entry["cluster_id"])
            suffix = re.sub(r'([a-z0-9])([A-Z])', r'\1-\2', suffix).lower()
            fn = f"{fn}-{suffix}"
            if fn in seen_names:
                fn = f"{entry['filename']}-{entry['cluster_id']}"
            entry["filename"] = fn
            print(f"    DEDUP: '{old}' -> '{fn}' (cluster {entry['cluster_id']})")
        seen_names[entry["filename"]] = entry["cluster_id"]

    # Pass 2: Force test-heavy clusters to L2
    test_kw = ["test", "tests", "bvt", "mock", "cvt"]
    for entry in all_labels:
        info = cluster_summaries.get(entry["cluster_id"], {})
        files = info.get("files", [])
        total = max(len(files), 1)
        test_ratio = sum(1 for f in files if any(k in f.lower() for k in test_kw)) / total

        if test_ratio > 0.7 and entry["layer"] != "L2-platform":
            old_layer = entry["layer"]
            entry["layer"] = "L2-platform"
            print(f"    LAYER-FIX: {entry['filename']} ({old_layer} -> L2-platform, test_ratio={test_ratio:.0%})")

    # Pass 3: Check for truly confusing near-duplicates (sim > 0.9) and fix via LLM
    filenames = [e["filename"] for e in all_labels]
    flagged = []
    for i in range(len(filenames)):
        for j in range(i + 1, len(filenames)):
            sim = SequenceMatcher(None, filenames[i], filenames[j]).ratio()
            if sim >= 0.9:
                flagged.append((i, j, sim, filenames[i], filenames[j]))

    if flagged:
        print(f"\n    {len(flagged)} near-duplicate pairs (>0.9 similarity) — requesting LLM rename...")

        rename_items = []
        for i, j, sim, name_a, name_b in flagged[:15]:
            info_a = cluster_summaries.get(all_labels[i]["cluster_id"], {})
            info_b = cluster_summaries.get(all_labels[j]["cluster_id"], {})
            rename_items.append(
                f"- '{name_a}' (cluster {all_labels[i]['cluster_id']}, "
                f"files: {', '.join(info_a.get('sample_names', [])[:5])}) "
                f"vs '{name_b}' (cluster {all_labels[j]['cluster_id']}, "
                f"files: {', '.join(info_b.get('sample_names', [])[:5])})"
            )

        all_current = ", ".join(sorted(set(filenames)))
        rename_prompt = f"""These DAG filenames are too similar and will confuse an AI agent navigating the docs.
Rename them to be more distinct. Keep the core concept but differentiate.

Confusing pairs:
{chr(10).join(rename_items)}

All current filenames (for reference): {all_current}

Return a JSON array of renames:
[{{"old_name": "xxx", "new_name": "yyy"}}, ...]
Only include names that NEED changing. No markdown fences."""

        prompt_file = output_dir / "_rename_prompt.txt"
        result_file = output_dir / "_rename_result.txt"
        prompt_file.write_text(rename_prompt, encoding="utf-8")
        if result_file.exists():
            result_file.unlink()

        try:
            subprocess.run(
                ["agency", "copilot", "-p",
                 f"Read {prompt_file.resolve()} and write output to {result_file.resolve()}. JSON only.",
                 "--no-default-mcps"],
                cwd=str(REPO_ROOT), capture_output=True, encoding="utf-8", errors="replace", timeout=120
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        if result_file.exists():
            raw = result_file.read_text(encoding="utf-8").strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            try:
                renames = json.loads(raw)
                rename_map = {r["old_name"]: r["new_name"] for r in renames}
                for entry in all_labels:
                    if entry["filename"] in rename_map:
                        old = entry["filename"]
                        entry["filename"] = rename_map[old]
                        print(f"    RENAME: '{old}' -> '{entry['filename']}'")
            except (json.JSONDecodeError, KeyError):
                print(f"    Could not parse rename results — skipping rename pass")

    return all_labels


def main():
    approach = get_approach()
    # Parse --batch-size CLI parameter
    BATCH_SIZE = DEFAULT_BATCH_SIZE
    for i, arg in enumerate(sys.argv):
        if arg == "--batch-size" and i + 1 < len(sys.argv):
            BATCH_SIZE = int(sys.argv[i + 1])

    OUTPUT_DIR = CLUSTERING_BASE / approach
    print(f"Step 2: Batched LLM Cluster Labeling")
    print(f"  Approach: {approach}")
    print(f"  Batch size: {BATCH_SIZE}")
    print(f"  Input/Output: {OUTPUT_DIR}")

    assignments, metadata, details, k = load_cluster_data(OUTPUT_DIR)
    print(f"  Loaded {len(assignments)} assignments across {k} clusters")

    cluster_summaries = build_cluster_summaries(assignments, metadata, details, k)
    print(f"  Built summaries for {len(cluster_summaries)} non-empty clusters")

    # Split into batches
    all_cids = sorted(cluster_summaries.keys())
    batches = [all_cids[i:i + BATCH_SIZE] for i in range(0, len(all_cids), BATCH_SIZE)]
    total_batches = len(batches)
    print(f"  Split into {total_batches} batches of ~{BATCH_SIZE}")

    # Process batches
    all_labels = []
    used_names = []

    for batch_idx, batch_cids in enumerate(batches):
        batch_summaries = {cid: cluster_summaries[cid] for cid in batch_cids}

        prompt = build_batch_prompt(batch_summaries, batch_idx, total_batches, used_names)
        print(f"\n  Batch {batch_idx + 1}/{total_batches} ({len(batch_cids)} clusters)...")

        batch_labels = None
        for attempt in range(1, DAG_LLM_RETRIES + 1):
            batch_labels = call_llm_batch(prompt, SYSTEM_PROMPT, OUTPUT_DIR, batch_idx)
            if batch_labels is not None:
                break
            if attempt < DAG_LLM_RETRIES:
                wait = DAG_LLM_RETRY_BACKOFF * (2 ** (attempt - 1))
                print(f"    Batch {batch_idx} attempt {attempt}/{DAG_LLM_RETRIES} failed — "
                      f"retrying in {wait:.0f}s...")
                time.sleep(wait)

        if batch_labels is None:
            # Fail loud: do NOT fabricate labels (the old fallback forced every cluster
            # in this batch to L2-platform, destroying the L1/L3 tiering). Abort so the
            # step can be re-run cleanly instead of shipping a degraded mapping.
            print(f"\n  [X] Batch {batch_idx} failed after {DAG_LLM_RETRIES} attempts "
                  f"(LLM timeout / unparseable / empty). Aborting labeling — no fabricated "
                  f"labels written. Re-run step 2 to retry.", file=sys.stderr)
            sys.exit(1)

        for entry in batch_labels:
            all_labels.append(entry)
            used_names.append(entry.get("filename", ""))
        print(f"    Got {len(batch_labels)} labels")

        # Brief pause between batches
        if batch_idx < total_batches - 1:
            time.sleep(2)

    print(f"\n{'='*60}")
    print(f"POST-PROCESSING: Validation & dedup")
    print(f"{'='*60}")

    all_labels = validate_and_fix_names(all_labels, cluster_summaries, OUTPUT_DIR)

    # Attach file lists and counts
    for entry in all_labels:
        cid = entry["cluster_id"]
        info = cluster_summaries.get(cid, {})
        entry["file_count"] = info.get("file_count", 0)
        entry["files"] = info.get("files", [])

    # Save
    with open(OUTPUT_DIR / "cluster_labels.json", "w", encoding="utf-8") as f:
        json.dump(all_labels, f, indent=2)

    # Summary
    print(f"\n{'='*60}")
    print(f"CLUSTER LABELS ({len(all_labels)} clusters)")
    print(f"{'='*60}")

    layer_counts = Counter()
    for entry in all_labels:
        layer = entry["layer"]
        layer_counts[layer] += 1
        print(f"  [{layer}] {entry['filename']}.md ({entry.get('file_count', '?')} files) — {entry.get('description', '')[:70]}")

    print(f"\nLayer distribution:")
    for layer, count in sorted(layer_counts.items()):
        print(f"  {layer}: {count} docs")

    # Near-duplicate check
    fns = [e["filename"] for e in all_labels]
    dup_85 = sum(1 for i in range(len(fns)) for j in range(i + 1, len(fns))
                 if SequenceMatcher(None, fns[i], fns[j]).ratio() >= 0.85)
    dup_70 = sum(1 for i in range(len(fns)) for j in range(i + 1, len(fns))
                 if SequenceMatcher(None, fns[i], fns[j]).ratio() >= 0.70)

    print(f"\nNear-duplicate names:")
    print(f"  >0.85 similarity: {dup_85} pairs")
    print(f"  >0.70 similarity: {dup_70} pairs")
    print(f"\nTotal DAG docs: {len(all_labels)}")
    print(f"Saved to: {OUTPUT_DIR / 'cluster_labels.json'}")


if __name__ == "__main__":
    main()
