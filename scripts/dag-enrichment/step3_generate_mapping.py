"""
Step 3: Generate compose_to_dag_mapping from cluster labels.

Supports two approaches:
  --approach text     (default) One-to-one mapping → compose_to_dag_mapping-text.json
  --approach symbols  One-to-many mapping → compose_to_dag_mapping-symbols.json
                      Each file has a primary DAG + optional secondary DAGs

For symbols approach:
  - Primary: the K-means cluster assignment
  - Secondary: other clusters that share imported namespaces with this file
  - Secondary entries include only key excerpts (not full content)

Usage:
    python scripts/dag-enrichment/step3_generate_mapping.py [--approach text|symbols]

Output:
    scripts/dag-enrichment/compose_to_dag_mapping-{text|symbols}.json
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

SCRIPT_DIR = Path(__file__).resolve().parent
CLUSTERING_BASE = SCRIPT_DIR / "output" / "clustering"


def get_approach():
    approach = "symbols"
    for i, arg in enumerate(sys.argv):
        if arg == "--approach" and i + 1 < len(sys.argv):
            approach = sys.argv[i + 1]
    if approach not in ("text", "symbols"):
        print(f"ERROR: Unknown approach '{approach}'. Use 'text' or 'symbols'.")
        sys.exit(1)
    return approach


def build_secondary_assignments_for_symbols(OUTPUT_DIR):
    """For symbols approach: read cross-references from step1_namespace_clustering.py output."""
    cross_refs_file = OUTPUT_DIR / "cross_references.json"
    if cross_refs_file.exists():
        with open(cross_refs_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def generate_text_mapping(labels, assignments, cluster_files, output_file):
    """Generate one-to-one mapping for text embeddings approach."""
    mappings = []
    for entry in sorted(labels, key=lambda e: (e["layer"], e["filename"])):
        cid = entry["cluster_id"]
        layer = entry["layer"]
        filename = entry["filename"]
        dag_doc = f"{layer}/{filename}.md"
        files = sorted(cluster_files.get(cid, []))

        dir_groups = defaultdict(list)
        for fp in files:
            parts = fp.replace("\\", "/").split("/")
            dir_path = "/".join(parts[:-1]) if len(parts) > 1 else ""
            dir_groups[dir_path].append(fp)

        compose_dirs = [dp if dp else df[0] for dp, df in sorted(dir_groups.items())]

        mappings.append({
            "dag_doc_new": dag_doc,
            "compose_dirs": compose_dirs,
            "compose_files": files,
            "description": entry.get("description", ""),
            "cluster_id": cid,
            "file_count": len(files),
        })

    mapping_json = {
        "_description": "Auto-generated mapping from TEXT EMBEDDING clustering. One-to-one: each file maps to exactly 1 DAG doc.",
        "_generated_by": "step3_generate_mapping.py --approach text",
        "_approach": "text",
        "_optimal_k": len(labels),
        "mappings": mappings,
        "ignored_patterns": [
            "*/obj/*", "*/bin/*", "*project.nuget.cache.md",
            "*.nuget.g.props.md", "*.nuget.g.targets.md", "*/owners.txt.md",
        ]
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(mapping_json, f, indent=2)
    return mappings


def generate_symbols_mapping(labels, assignments, cluster_files, metadata, label_lookup, output_file, OUTPUT_DIR):
    """Generate mapping for namespace-based clustering with cross-references."""
    cross_refs = build_secondary_assignments_for_symbols(OUTPUT_DIR)

    # Load cluster_details for min_ns_list and defining_ns
    cluster_details = {}
    details_file = OUTPUT_DIR / "cluster_details.json"
    if details_file.exists():
        with open(details_file, "r", encoding="utf-8") as f:
            cluster_details = json.load(f)

    # Build cluster_id -> dag_doc lookup
    cid_to_dag = {}
    for entry in labels:
        cid_to_dag[entry["cluster_id"]] = f"{entry['layer']}/{entry['filename']}.md"

    mappings = []
    for entry in sorted(labels, key=lambda e: (e["layer"], e["filename"])):
        cid = entry["cluster_id"]
        cid_str = str(cid)
        dag_doc = cid_to_dag[cid]
        files = sorted(cluster_files.get(cid, []))

        # Cross-referenced DAG docs (from imported namespaces)
        ref_cluster_ids = cross_refs.get(cid_str, [])
        referenced_dags = [cid_to_dag[r] for r in ref_cluster_ids if r in cid_to_dag]

        # Get namespace info from cluster details
        detail = cluster_details.get(cid_str, {})

        dir_groups = defaultdict(list)
        for fp in files:
            parts = fp.replace("\\", "/").split("/")
            dir_path = "/".join(parts[:-1]) if len(parts) > 1 else ""
            dir_groups[dir_path].append(fp)
        compose_dirs = [dp if dp else df[0] for dp, df in sorted(dir_groups.items())]

        mappings.append({
            "dag_doc_new": dag_doc,
            "compose_dirs": compose_dirs,
            "compose_files": files,
            "description": entry.get("description", ""),
            "cluster_id": cid,
            "file_count": len(files),
            "defining_namespace": detail.get("defining_ns", ""),
            "min_namespace_list": detail.get("min_ns_list", []),
            "cross_referenced_dags": referenced_dags,
            "cross_ref_count": len(referenced_dags),
        })

    mapping_json = {
        "_description": "Auto-generated mapping from NAMESPACE clustering. Cross-references link DAGs via imported namespaces.",
        "_generated_by": "step3_generate_mapping.py --approach symbols",
        "_approach": "symbols (namespace-based)",
        "_optimal_k": len(labels),
        "_note": "cross_referenced_dags = other DAG docs that this DAG's files import namespaces from.",
        "mappings": mappings,
        "ignored_patterns": [
            "*/obj/*", "*/bin/*", "*project.nuget.cache.md",
            "*.nuget.g.props.md", "*.nuget.g.targets.md", "*/owners.txt.md",
        ]
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(mapping_json, f, indent=2)
    return mappings


def main():
    approach = get_approach()
    OUTPUT_DIR = CLUSTERING_BASE / approach
    MAPPING_FILE = SCRIPT_DIR / f"compose_to_dag_mapping-{approach}.json"

    print(f"Approach: {approach}")
    print(f"Input: {OUTPUT_DIR}")
    print(f"Output: {MAPPING_FILE}")

    with open(OUTPUT_DIR / "cluster_labels.json", "r", encoding="utf-8") as f:
        labels = json.load(f)
    with open(OUTPUT_DIR / "cluster_assignments.json", "r", encoding="utf-8") as f:
        assignments = json.load(f)

    cluster_files = defaultdict(list)
    for file_path, cid in assignments.items():
        cluster_files[cid].append(file_path)

    label_lookup = {entry["cluster_id"]: entry for entry in labels}

    # Load metadata (needed for symbols approach)
    metadata = {}
    meta_file = OUTPUT_DIR / "file_metadata.json"
    if meta_file.exists():
        with open(meta_file, "r", encoding="utf-8") as f:
            metadata = json.load(f)

    if approach == "text":
        mappings = generate_text_mapping(labels, assignments, cluster_files, MAPPING_FILE)
    else:
        mappings = generate_symbols_mapping(labels, assignments, cluster_files, metadata, label_lookup, MAPPING_FILE, OUTPUT_DIR)

    # Summary
    layer_counts = defaultdict(int)
    for entry in mappings:
        layer = entry["dag_doc_new"].split("/")[0]
        layer_counts[layer] += 1

    print(f"{'='*60}")
    print(f"GENERATED {MAPPING_FILE.name}")
    print(f"{'='*60}")
    print(f"Approach: {approach}")
    print(f"Total DAG docs: {len(mappings)}")
    for layer, count in sorted(layer_counts.items()):
        print(f"  {layer}: {count} docs")

    print(f"\nPer-doc file counts:")
    for entry in sorted(mappings, key=lambda e: -e.get("file_count", 0)):
        dag = entry["dag_doc_new"]
        c = entry.get("file_count", 0)
        if approach == "symbols":
            refs = entry.get("cross_ref_count", 0)
            print(f"  {c:4d} files | {refs:2d} cross-refs → {dag}")
        else:
            print(f"  {c:4d} files → {dag}")

    if approach == "symbols":
        total_refs = sum(e.get("cross_ref_count", 0) for e in mappings)
        print(f"\n  Total cross-references: {total_refs}")
        print(f"  Avg cross-refs per DAG: {total_refs / max(len(mappings), 1):.1f}")

    print(f"\nMapping written to: {MAPPING_FILE}")


if __name__ == "__main__":
    main()
