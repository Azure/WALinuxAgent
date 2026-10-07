"""
Step 1 (Symbols V2): Namespace-based clustering — group files by their defining namespace.

Instead of K-means on binary vectors, this directly groups files by their defining namespace,
then builds cross-references between DAGs based on imported namespaces.

Algorithm:
  1. For each .cs.md file, extract its defining namespace (the shortest common prefix
     of all symbols that "belong" to this file's class)
  2. Group files by defining namespace → each group = 1 cluster/DAG doc
  3. For each cluster, compute the "minimum namespace list" (deduped prefixes)
  4. Build a central namespace → DAG lookup table
  5. For each DAG, resolve imported namespaces to other DAGs → cross-references

Output:
    scripts/dag-enrichment/output/clustering/symbols/
        cluster_assignments.json     (file → cluster_id, one-to-one by defining NS)
        cluster_details.json         (cluster_id → {defining_ns, files, min_ns_list, cross_refs})
        namespace_to_dag.json        (namespace → cluster_id, the central lookup)
        cross_references.json        (dag → [referenced_dags])
        elbow_results.json           (compatibility: stores optimal_k)

Usage:
    python scripts/dag-enrichment/step1_namespace_clustering.py
"""

import json
import math
import re
import sys
from pathlib import Path
from collections import defaultdict, Counter

OUTPUT_DIR = Path(__file__).resolve().parent / "output" / "clustering" / "symbols"

# Default minimum files per cluster. Clusters smaller than this get merged into parent namespace.
DEFAULT_MIN_CLUSTER_SIZE = 5

# Absolute floor/ceiling for the adaptive maximum cluster size (per-repo, computed
# from the file count). MAX_CLUSTER_SIZE is no longer a fixed constant.
MIN_MAX_CLUSTER_SIZE = 25
MAX_MAX_CLUSTER_SIZE = 120
# Multiplier for the sqrt-based adaptive ceiling.
MAX_SIZE_SQRT_FACTOR = 2.5


def auto_max_cluster_size(n_files: int) -> int:
    """Adaptive per-repo ceiling on cluster size.

    Grows sub-linearly (~sqrt) with the number of files so that tiny repos do
    not over-split and huge repos do not produce unreadable mega-clusters.
    Clamped to [MIN_MAX_CLUSTER_SIZE, MAX_MAX_CLUSTER_SIZE].
    """
    base = round(MAX_SIZE_SQRT_FACTOR * math.sqrt(max(n_files, 1)))
    return max(MIN_MAX_CLUSTER_SIZE, min(base, MAX_MAX_CLUSTER_SIZE))


def load_metadata():
    with open(OUTPUT_DIR / "file_metadata.json", "r", encoding="utf-8") as f:
        return json.load(f)


def get_defining_namespace(metadata_entry: dict) -> str:
    """Get the defining namespace for a file.
    Uses the full 'defining_ns' from step0_extract_symbols.py (no truncation).
    If multiple defining namespaces, pick the most specific one.
    Then strip member-level names to get the class-level namespace."""
    defining = metadata_entry.get("defining_ns", [])
    if not defining:
        all_ns = metadata_entry.get("all_ns", [])
        if all_ns:
            defining = [all_ns[0]]
        else:
            return "UNKNOWN"

    # Pick the most specific (longest) defining namespace
    best = max(defining, key=len)

    # Strip member-level names: remove parts that look like method/property names
    # (start with lowercase, or are get_/set_ accessors)
    parts = best.split(".")
    ns_parts = []
    for p in parts:
        if p.startswith("get_") or p.startswith("set_"):
            break
        if p and p[0].islower():
            break
        ns_parts.append(p)

    return ".".join(ns_parts) if ns_parts else best


def compute_minimum_namespace_list(symbols: list[str]) -> list[str]:
    """Given a list of FQN symbols, compute the minimum common namespace prefixes.

    Example:
      Input:  [...FSM.Backup.BackupBlock.plHostSendAndGetResponseBlock,
               ...FSM.Backup.BackupBlock.BackupBlock,
               ...FSM.Backup.BackupBlock.BackupParamsPrep]
      Output: [...FSM.Backup.BackupBlock]

    For each symbol, we walk up the hierarchy until we find the shortest prefix
    that is shared by at least 2 symbols (or use the full class-level prefix).
    Then deduplicate.
    """
    if not symbols:
        return []

    # Extract "class-level" prefixes: everything up to and including the class name
    # A class name is typically the last PascalCase segment before member names
    class_prefixes = set()
    for sym in symbols:
        parts = sym.split(".")
        # Find the class-level: walk from left, stop at the first part that looks like
        # a member (starts with lowercase, or is get_/set_)
        class_level = []
        for p in parts:
            if p.startswith("get_") or p.startswith("set_") or (p[0].islower() if p else False):
                break
            class_level.append(p)
        if class_level:
            class_prefixes.add(".".join(class_level))

    if not class_prefixes:
        return list(set(symbols))

    # Now reduce: if A is a prefix of B, keep only A
    sorted_prefixes = sorted(class_prefixes, key=len)
    minimal = []
    for prefix in sorted_prefixes:
        # Check if any already-added prefix is a prefix of this one
        if not any(prefix.startswith(m + ".") for m in minimal):
            minimal.append(prefix)

    return sorted(minimal)


def _common_prefix_len(seqs: list) -> int:
    """Number of leading segments shared by ALL sequences."""
    if not seqs:
        return 0
    shortest = min(len(s) for s in seqs)
    n = 0
    for i in range(shortest):
        token = seqs[0][i]
        if all(s[i] == token for s in seqs):
            n += 1
        else:
            break
    return n


def _file_namespace_segs(fp: str, metadata: dict) -> list:
    return get_defining_namespace(metadata[fp]).split(".")


def _file_dir_segs(fp: str) -> list:
    return fp.replace("\\", "/").split("/")[:-1]


def _partition_by(files: list, seg_fn) -> dict:
    """Partition files by the segment one level below their deepest common prefix."""
    seqs = {fp: seg_fn(fp) for fp in files}
    cp = _common_prefix_len(list(seqs.values()))
    buckets = defaultdict(list)
    for fp in files:
        segs = seqs[fp]
        key = tuple(segs[:cp + 1]) if len(segs) > cp else tuple(segs)
        buckets[key].append(fp)
    return buckets


def _best_partition(files: list, metadata: dict):
    """Choose the partition (namespace trie vs directory trie) that makes the
    most progress — i.e. the one whose largest bucket is smallest. Returns None
    if neither signal can split the set (guarantees termination since any chosen
    partition's largest bucket is strictly smaller than the input)."""
    total = len(files)
    candidates = []
    ns_buckets = _partition_by(files, lambda fp: _file_namespace_segs(fp, metadata))
    dir_buckets = _partition_by(files, _file_dir_segs)
    # Namespace first so it wins ties (semantic grouping preferred over structural).
    for kind, buckets in (("ns", ns_buckets), ("dir", dir_buckets)):
        if len(buckets) > 1:
            largest = max(len(v) for v in buckets.values())
            if largest < total:
                candidates.append((largest, 0 if kind == "ns" else 1, buckets))
    if not candidates:
        return None
    candidates.sort(key=lambda c: (c[0], c[1]))
    return candidates[0][2]


def subdivide_cluster(files: list, max_size: int, min_size: int, metadata: dict) -> list:
    """Recursively break an oversized file set into <= max_size leaves.

    At each level picks the more balanced of the namespace trie (semantic) and
    directory trie (structural) — the latter is what rescues flat mega-namespaces
    like a single `Microsoft.BackupManagementService`. Sub-min buckets are rolled
    into one residual leaf rather than fragmenting into singletons. Returns a list
    of file lists (leaves)."""
    if len(files) <= max_size:
        return [files]
    buckets = _best_partition(files, metadata)
    if buckets is None:
        # Neither signal can subdivide further; emit as-is (best effort).
        return [files]
    leaves = []
    residual = []
    for fs in buckets.values():
        if len(fs) < min_size:
            residual.extend(fs)
        else:
            leaves.extend(subdivide_cluster(fs, max_size, min_size, metadata))
    if residual:
        leaves.append(residual)
    return leaves


def _pascal(text: str) -> str:
    return "".join(w[:1].upper() + w[1:] for w in re.split(r"[^A-Za-z0-9]+", text) if w)


def label_for_files(files: list, metadata: dict) -> str:
    """Synthesize a namespace-shaped defining_ns label for a split leaf."""
    ns_seqs = [_file_namespace_segs(fp, metadata) for fp in files]
    cp = _common_prefix_len(ns_seqs)
    if cp > 0:
        base = ".".join(ns_seqs[0][:cp])
    else:
        base = ns_seqs[0][0] if ns_seqs and ns_seqs[0] else "Cluster"
    # Disambiguate flat namespaces with the deepest common directory segment.
    dir_seqs = [_file_dir_segs(fp) for fp in files]
    dcp = _common_prefix_len(dir_seqs)
    if dcp > 0:
        tail = _pascal(dir_seqs[0][dcp - 1])
        if tail and not base.lower().endswith(tail.lower()):
            return f"{base}.{tail}"
    return base


def _dedupe_labels(groups: list) -> list:
    """Ensure defining_ns labels are unique across clusters."""
    seen = {}
    out = []
    for ns, files in groups:
        label = ns
        if label in seen:
            dir_seqs = [_file_dir_segs(fp) for fp in files]
            dcp = _common_prefix_len(dir_seqs)
            suffix = _pascal(dir_seqs[0][dcp - 1]) if dcp > 0 else ""
            candidate = f"{ns}.{suffix}" if suffix else ns
            i = 2
            while candidate in seen:
                candidate = f"{ns}.{suffix}{i}" if suffix else f"{ns}.{i}"
                i += 1
            label = candidate
        seen[label] = True
        out.append((label, files))
    return out


def build_namespace_to_dag_lookup(clusters: dict) -> dict:
    """Build a central lookup: namespace_prefix → cluster_id.

    For each cluster, register all its minimum namespace prefixes.
    This allows other DAGs to find which DAG "owns" a namespace.
    """
    ns_to_dag = {}
    for cid, info in clusters.items():
        for ns in info["min_ns_list"]:
            ns_to_dag[ns] = cid
        # Also register the defining namespace itself
        ns_to_dag[info["defining_ns"]] = cid
    return ns_to_dag


def resolve_cross_references(clusters: dict, ns_to_dag: dict) -> dict:
    """For each cluster, find which other DAGs it references.

    For each namespace in a cluster's imported namespaces:
      - Look up in ns_to_dag
      - If not found, walk up the namespace hierarchy until a match is found
      - If the matched DAG is different from this cluster → cross-reference
    """
    cross_refs = {}

    for cid, info in clusters.items():
        refs = set()
        all_imported = set()
        for file_meta in info["file_metadata"]:
            all_imported.update(file_meta.get("imported_ns", []))

        for ns in all_imported:
            # Try exact match first
            target = ns_to_dag.get(ns)
            if target is None:
                # Walk up the hierarchy
                parts = ns.split(".")
                for depth in range(len(parts) - 1, 0, -1):
                    prefix = ".".join(parts[:depth])
                    target = ns_to_dag.get(prefix)
                    if target is not None:
                        break

            if target is not None and target != cid:
                refs.add(target)

        cross_refs[cid] = sorted(refs)

    return cross_refs


def main():
    # Parse --min-cluster-size CLI parameter
    min_cluster_size = DEFAULT_MIN_CLUSTER_SIZE
    for i, arg in enumerate(sys.argv):
        if arg == "--min-cluster-size" and i + 1 < len(sys.argv):
            min_cluster_size = int(sys.argv[i + 1])
    print(f"Using MIN_CLUSTER_SIZE = {min_cluster_size}")

    # Parse --max-cluster-size CLI parameter (default: adaptive per-repo)
    max_cluster_size = None
    for i, arg in enumerate(sys.argv):
        if arg == "--max-cluster-size" and i + 1 < len(sys.argv):
            max_cluster_size = int(sys.argv[i + 1])

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    metadata = load_metadata()
    print(f"Loaded metadata for {len(metadata)} files")

    if max_cluster_size is None:
        max_cluster_size = auto_max_cluster_size(len(metadata))
        print(f"Using MAX_CLUSTER_SIZE = {max_cluster_size} (auto, from {len(metadata)} files)")
    else:
        print(f"Using MAX_CLUSTER_SIZE = {max_cluster_size} (override)")

    # Step 1: Group files by defining namespace
    ns_groups = defaultdict(list)  # namespace → [file_paths]
    file_to_ns = {}

    for file_path, meta in metadata.items():
        defining_ns = get_defining_namespace(meta)
        ns_groups[defining_ns].append(file_path)
        file_to_ns[file_path] = defining_ns

    print(f"Found {len(ns_groups)} unique defining namespaces")

    # Step 2: Merge small namespace groups into parent namespaces
    # If a namespace has fewer than MIN_CLUSTER_SIZE files, merge it into its parent.
    # Repeat until no more merges happen.
    merged = True
    merge_rounds = 0
    while merged:
        merged = False
        merge_rounds += 1
        new_ns_groups = defaultdict(list)
        # Parent sizes snapshot at round start, used by the merge guard below.
        round_sizes = {n: len(fs) for n, fs in ns_groups.items()}

        for ns, files in sorted(ns_groups.items()):
            if len(files) < min_cluster_size:
                # Try to merge into parent namespace, unless the parent is already
                # at/over the size ceiling (merge guard) — this stops unrelated
                # small namespaces from snowballing into one mega-cluster.
                parts = ns.split(".")
                parent_ns = ".".join(parts[:-1]) if len(parts) > 1 else None
                if (parent_ns is not None
                        and round_sizes.get(parent_ns, 0) < max_cluster_size
                        and len(new_ns_groups[parent_ns]) + len(files) <= max_cluster_size):
                    new_ns_groups[parent_ns].extend(files)
                    merged = True
                else:
                    new_ns_groups[ns].extend(files)
            else:
                new_ns_groups[ns].extend(files)

        # Also check: if merging created a group that's too large AND has sub-namespaces,
        # don't merge (keep the originals). But for simplicity, just do the merge.
        ns_groups = new_ns_groups

    print(f"After {merge_rounds} merge rounds: {len(ns_groups)} clusters (pre-split)")

    # Update file_to_ns after merges
    file_to_ns = {}
    for ns, files in ns_groups.items():
        for fp in files:
            file_to_ns[fp] = ns

    # Step 2b: Split oversized clusters back down so none exceeds the adaptive
    # ceiling. Uses the namespace trie first, then the directory trie as a
    # fallback for flat mega-namespaces.
    final_groups = []
    split_count = 0
    for ns, files in sorted(ns_groups.items()):
        if len(files) <= max_cluster_size:
            final_groups.append((ns, files))
            continue
        leaves = subdivide_cluster(files, max_cluster_size, min_cluster_size, metadata)
        if len(leaves) <= 1:
            final_groups.append((ns, files))
        else:
            split_count += 1
            for leaf in leaves:
                final_groups.append((label_for_files(leaf, metadata), leaf))
    final_groups = _dedupe_labels(final_groups)
    if split_count:
        print(f"Split pass: subdivided {split_count} oversized cluster(s) -> {len(final_groups)} groups")

    # Step 3: Create clusters (each final group = 1 cluster)
    clusters = {}
    assignments = {}
    ns_to_cluster_id = {}

    for cid, (ns, files) in enumerate(final_groups):
        # Collect all symbols from files in this cluster
        all_symbols = []
        file_metas = []
        for fp in files:
            meta = metadata[fp]
            all_symbols.extend(meta.get("symbols", []))
            file_metas.append(meta)
            assignments[fp] = cid

        # Compute minimum namespace list for this cluster
        min_ns_list = compute_minimum_namespace_list(all_symbols)

        clusters[cid] = {
            "cluster_id": cid,
            "defining_ns": ns,
            "files": sorted(files),
            "file_count": len(files),
            "min_ns_list": min_ns_list,
            "file_metadata": file_metas,
        }
        ns_to_cluster_id[ns] = cid

    K = len(clusters)
    print(f"Created {K} clusters")

    # Step 3: Build central namespace → DAG lookup
    ns_to_dag = build_namespace_to_dag_lookup(clusters)
    print(f"Namespace lookup has {len(ns_to_dag)} entries")

    # Step 4: Resolve cross-references
    cross_refs = resolve_cross_references(clusters, ns_to_dag)
    total_refs = sum(len(refs) for refs in cross_refs.values())
    print(f"Cross-references: {total_refs} total ({total_refs / max(K, 1):.1f} avg per DAG)")

    # Step 5: Print summary
    print(f"\n{'='*60}")
    print(f"NAMESPACE-BASED CLUSTERING RESULTS")
    print(f"{'='*60}")

    # Sort by file count descending
    sorted_clusters = sorted(clusters.values(), key=lambda c: -c["file_count"])

    print(f"\nTop 20 clusters by size:")
    for c in sorted_clusters[:20]:
        refs = cross_refs.get(c["cluster_id"], [])
        print(f"  {c['file_count']:4d} files | {len(refs):2d} refs | {c['defining_ns']}")

    sizes = [c["file_count"] for c in sorted_clusters]
    print(f"\n  Total clusters: {K}")
    print(f"  Min: {min(sizes)}, Max: {max(sizes)}, Median: {sorted(sizes)[len(sizes)//2]}")
    print(f"  Clusters with 1 file: {sum(1 for s in sizes if s == 1)}")
    print(f"  Clusters with >50 files: {sum(1 for s in sizes if s > 50)}")

    # Step 6: Save outputs
    with open(OUTPUT_DIR / "cluster_assignments.json", "w", encoding="utf-8") as f:
        json.dump(assignments, f, indent=2)

    # Save cluster details (strip file_metadata for smaller file)
    cluster_details = {}
    for cid, info in clusters.items():
        cluster_details[cid] = {
            "cluster_id": cid,
            "defining_ns": info["defining_ns"],
            "files": info["files"],
            "file_count": info["file_count"],
            "min_ns_list": info["min_ns_list"],
            "cross_references": cross_refs.get(cid, []),
        }
    with open(OUTPUT_DIR / "cluster_details.json", "w", encoding="utf-8") as f:
        json.dump(cluster_details, f, indent=2)

    with open(OUTPUT_DIR / "namespace_to_dag.json", "w", encoding="utf-8") as f:
        json.dump(ns_to_dag, f, indent=2)

    with open(OUTPUT_DIR / "cross_references.json", "w", encoding="utf-8") as f:
        json.dump(cross_refs, f, indent=2)

    # Compatibility: write elbow_results.json (needed by step2)
    with open(OUTPUT_DIR / "elbow_results.json", "w", encoding="utf-8") as f:
        json.dump({
            "optimal_k": K,
            "method": "namespace-based (not elbow)",
            "cluster_sizes": {str(c["cluster_id"]): c["file_count"] for c in sorted_clusters},
        }, f, indent=2)

    print(f"\nOutput saved to: {OUTPUT_DIR}")
    print(f"\nFiles written:")
    print(f"  cluster_assignments.json   ({len(assignments)} file → cluster mappings)")
    print(f"  cluster_details.json       ({K} clusters with min_ns_list + cross-refs)")
    print(f"  namespace_to_dag.json      ({len(ns_to_dag)} namespace → cluster entries)")
    print(f"  cross_references.json      ({total_refs} cross-references)")
    print(f"  elbow_results.json         (compatibility: optimal_k={K})")


if __name__ == "__main__":
    main()
