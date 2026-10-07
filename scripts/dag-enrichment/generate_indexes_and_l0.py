"""
Generate L0 primer and docs-index.md files for final-level DAGs.

Scans the final-DAGs directory for all .md files across L1/L2/L3, then generates:
  1. L0-foundations/codebase-primer.md — LLM-synthesized from layer docs-index content
  2. docs-index.md — master index with links to all layer indexes + LLM reading chains
  3. L1-conceptual/docs-index.md — index of all L1 docs
  4. L2-platform/docs-index.md — index of all L2 docs
  5. L3-flows/docs-index.md — index of all L3 docs

The L0 primer and reading chains are generated via a single LLM call that receives
the layer docs-index.md content (document names + TL;DR descriptions) as context.

Only for final-level DAGs. Intermediate DAGs do not need L0/docs-index (1:1 mapping from final).

Usage:
    python scripts/dag-enrichment/generate_indexes_and_l0.py \
        --dag-dir copilot-docs

    python scripts/dag-enrichment/generate_indexes_and_l0.py \
        --dag-dir copilot-docs --intermediate-dir intermediate-docs
"""

import argparse
import json
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
LOG_DIR = Path(__file__).resolve().parent / "output" / "enrichment-logs"

L0_FILENAME = "codebase-primer.md"
L0_MAX_LINES = 200

LAYER_DESCRIPTIONS = {
    "L1-conceptual": '"What is X?" — Foundational concepts, architecture, design rationale.',
    "L2-platform": '"How does X work?" — Infrastructure services, build, deployment, telemetry, flighting.',
    "L3-flows": '"How to implement X?" — End-to-end flows composing L1 concepts and L2 platform services.',
}


def extract_tldr(filepath: Path) -> str:
    """Extract the first meaningful line after the title as a description."""
    try:
        text = filepath.read_text(encoding="utf-8")
    except Exception:
        return filepath.stem.replace("-", " ").title()

    # Try to find "> TL;DR:" or first paragraph after title
    tldr = re.search(r'>\s*TL;?DR:?\s*(.+)', text)
    if tldr:
        return tldr.group(1).strip()[:150]

    # Fallback: first non-empty, non-heading line
    for line in text.split("\n"):
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith(">") and not line.startswith("-"):
            return line[:150]

    return filepath.stem.replace("-", " ").title()


def collect_dag_docs(dag_dir: Path) -> dict[str, list[tuple[str, str]]]:
    """Collect all .md docs per layer, returning {layer: [(filename, description)]}."""
    layers = {}
    for layer in ["L1-conceptual", "L2-platform", "L3-flows"]:
        layer_dir = dag_dir / layer
        if not layer_dir.exists():
            continue
        docs = []
        for md in sorted(layer_dir.glob("*.md")):
            if md.name == "docs-index.md":
                continue
            desc = extract_tldr(md)
            docs.append((md.name, desc))
        if docs:
            layers[layer] = docs
    return layers


def generate_layer_index(dag_dir: Path, layer: str, docs: list[tuple[str, str]]):
    """Generate a docs-index.md for a specific layer."""
    layer_dir = dag_dir / layer
    layer_dir.mkdir(parents=True, exist_ok=True)
    index_file = layer_dir / "docs-index.md"

    layer_desc = LAYER_DESCRIPTIONS.get(layer, "")

    lines = [
        f"# {layer.replace('-', ' — ', 1).title()} Documentation Index\n",
        f"> {layer_desc}\n",
        "",
        "| Document | Description |",
        "|----------|-------------|",
    ]
    for name, desc in docs:
        lines.append(f"| [{name}]({name}) | {desc} |")

    index_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  Created: {index_file.relative_to(dag_dir)}")


def get_repo_name() -> str:
    """Derive the repo name from the REPO_ROOT directory name."""
    return REPO_ROOT.name


def call_copilot_cli(prompt: str, result_file: Path, timeout: int = 600) -> str | None:
    """Call agency copilot CLI and read the result from file."""
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


def build_layer_index_context(dag_dir: Path, layers: dict) -> str:
    """Read the generated layer docs-index.md files and concatenate them as context for the LLM."""
    parts = []
    for layer in ["L1-conceptual", "L2-platform", "L3-flows"]:
        if layer not in layers:
            continue
        index_file = dag_dir / layer / "docs-index.md"
        if index_file.exists():
            content = index_file.read_text(encoding="utf-8")
            parts.append(f"=== {layer}/docs-index.md ===\n{content}")
    return "\n\n".join(parts)


def generate_master_index(dag_dir: Path, layers: dict, reading_chains_text: str,
                          intermediate_dir: Path | None = None):
    """Generate the master docs-index.md at the root of the DAG directory."""
    index_file = dag_dir / "docs-index.md"
    repo_name = get_repo_name()

    lines = [
        f"# Documentation Index — {repo_name}\n",
        "> Master index for all agent-optimized documentation. Read this FIRST for any non-trivial question.\n",
        "",
        "## Always-Loaded Foundation\n",
        f"- [L0 Primer](L0-foundations/{L0_FILENAME}) — Architecture, terminology, ownership. Always read before any task.\n",
        "",
        "## Layer Indexes\n",
    ]

    for layer in ["L1-conceptual", "L2-platform", "L3-flows"]:
        if layer in layers:
            desc = LAYER_DESCRIPTIONS.get(layer, "")
            lines.append(f"- [{layer.replace('-', ' — ', 1).title()}]({layer}/docs-index.md) — {desc}")

    # Add detailed content fallback section if intermediate dir exists
    if intermediate_dir and intermediate_dir.exists():
        rel_intermediate = ""
        try:
            rel_intermediate = str(intermediate_dir.relative_to(REPO_ROOT)).replace("\\", "/")
        except ValueError:
            rel_intermediate = str(intermediate_dir)

        lines.extend([
            "",
            "## Detailed Content Fallback\n",
            f"Every DAG doc has a corresponding **detailed content file** at `{rel_intermediate}/` "
            "with per-file NL summaries. When a compact DAG doc (~200 lines) lacks sufficient detail:\n",
            "1. Read the compact DAG doc in `{layer}/{name}.md`",
            f"2. If insufficient, read `{rel_intermediate}/{{layer}}/{{name}}.content.md` (detailed, no line limit)",
            "3. Only then search source code directly",
        ])

    # Append LLM-generated reading chains
    if reading_chains_text:
        lines.extend([
            "",
            "## Reading Chains\n",
            "Ordered document sequences for common query types. Follow in order.\n",
            reading_chains_text,
        ])
    else:
        lines.extend([
            "",
            "## Reading Chains\n",
            "Ordered document sequences for common query types. Follow in order.\n",
            "> Reading chains could not be generated. Navigate via the layer indexes above.\n",
        ])

    index_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  Created: docs-index.md")


def generate_l0_and_chains(dag_dir: Path, layers: dict) -> str:
    """Generate L0 primer and reading chains via a single LLM call.

    Sends the layer docs-index.md content (document names + descriptions) to the LLM
    and asks it to produce:
      1. The L0 primer file content
      2. Reading chains for the master docs-index.md

    Returns the reading chains text (L0 file is written directly).
    """
    l0_dir = dag_dir / "L0-foundations"
    l0_dir.mkdir(parents=True, exist_ok=True)
    l0_file = l0_dir / L0_FILENAME

    repo_name = get_repo_name()
    layer_context = build_layer_index_context(dag_dir, layers)

    if not layer_context.strip():
        print("    WARNING: No layer index content found — falling back to minimal L0")
        _write_minimal_l0(l0_file, repo_name, layers)
        return ""

    prompt = f"""You are generating two outputs from a set of DAG documentation indexes.

## CONTEXT — Layer Documentation Indexes
These list every DAG document in the codebase with a short description:

{layer_context}

## OUTPUT 1: L0 Foundation Primer
Generate a codebase primer for the repository "{repo_name}".

The primer is ALWAYS loaded into every AI agent session. It is the irreducible minimum
that makes all other docs useful.

HARD RULES for the L0 primer:
- Start with: # {repo_name} — Primer
- Second line must be blank
- Third line must be: > Always-loaded foundation. Max {L0_MAX_LINES} lines. No index.
- Must contain these sections in this order:
  ## Architecture — High-level system architecture
  ## Request Flow — Typical request/operation flow through the system (can use ASCII diagram)
  ## Core Terminology — Table with Term | Definition for the 10-20 most important concepts
  ## Key Components — Table with Component | Description summarizing the major subsystems
- Max {L0_MAX_LINES} lines total
- NO code snippets, only class/component names as references
- Synthesize from the document names and descriptions above — identify the key architectural patterns

## OUTPUT 2: Reading Chains
Generate 3-6 reading chains — ordered sequences of DAG documents for common developer tasks.
Each chain should use the actual document paths from the indexes above (e.g., L1-conceptual/foo.md).
Every chain should start with L0-foundations/{L0_FILENAME}.

Format each chain as:
### "Question or task description"
1. [L0-foundations/{L0_FILENAME}](L0-foundations/{L0_FILENAME})
2. [layer/doc-name.md](layer/doc-name.md)
3. ...

## OUTPUT FORMAT
Return a JSON object with exactly two keys:
- "l0_content": the full text of the L0 primer (as a single string with newlines)
- "reading_chains": the full text of the reading chains section (as a single string with newlines)

Return ONLY the JSON object. No markdown fences. No explanation."""

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    result_file = LOG_DIR / "_l0_and_chains_result.json"

    print("    Calling LLM to generate L0 primer and reading chains...")
    result = call_copilot_cli(prompt, result_file)

    if not result:
        print("    WARNING: LLM call failed — falling back to minimal L0")
        _write_minimal_l0(l0_file, repo_name, layers)
        return ""

    # Parse the JSON response
    try:
        # Try direct JSON parse
        data = json.loads(result)
    except json.JSONDecodeError:
        # Try extracting JSON from the text
        match = re.search(r'\{[\s\S]*\}', result)
        if match:
            try:
                data = json.loads(match.group())
            except json.JSONDecodeError:
                print("    WARNING: Could not parse LLM JSON response — falling back to minimal L0")
                _write_minimal_l0(l0_file, repo_name, layers)
                return ""
        else:
            print("    WARNING: No JSON found in LLM response — falling back to minimal L0")
            _write_minimal_l0(l0_file, repo_name, layers)
            return ""

    l0_content = data.get("l0_content", "")
    reading_chains = data.get("reading_chains", "")

    if not l0_content:
        print("    WARNING: LLM returned empty L0 content — falling back to minimal L0")
        _write_minimal_l0(l0_file, repo_name, layers)
    else:
        # Write L0 primer
        l0_lines = l0_content.split("\n")
        if len(l0_lines) > L0_MAX_LINES:
            l0_lines = l0_lines[:L0_MAX_LINES - 2]
            l0_lines.append("")
            l0_lines.append(f"> Truncated to {L0_MAX_LINES} lines. See L1 docs for full details.")
        l0_file.write_text("\n".join(l0_lines) + "\n", encoding="utf-8")
        print(f"    Created: L0-foundations/{L0_FILENAME} ({len(l0_lines)} lines)")

    return reading_chains


def _write_minimal_l0(l0_file: Path, repo_name: str, layers: dict):
    """Write a minimal L0 primer when LLM is unavailable."""
    lines = [
        f"# {repo_name} — Primer",
        "",
        f"> Always-loaded foundation. Max {L0_MAX_LINES} lines. No index.",
        "",
        "## Architecture",
        "",
        f"This is the foundation primer for the {repo_name} codebase.",
        "Refer to layer indexes for detailed documentation.",
        "",
        "## Request Flow",
        "",
        "> To be generated. See L3-flows documents for operational workflows.",
        "",
        "## Key Components",
        "",
    ]

    # Add summaries from L1 docs
    l1_docs = layers.get("L1-conceptual", [])
    if l1_docs:
        lines.append("| Component | Description |")
        lines.append("|-----------|-------------|")
        for name, desc in l1_docs[:20]:
            component = name.replace(".md", "").replace("-", " ").title()
            lines.append(f"| {component} | {desc[:100]} |")

    l0_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"    Created (minimal fallback): L0-foundations/{L0_FILENAME} ({len(lines)} lines)")


def main():
    parser = argparse.ArgumentParser(description="Generate L0 primer and docs-index files for final-level DAGs")
    default_dag_dir = str(REPO_ROOT / "copilot-docs")
    parser.add_argument("--dag-dir", default=default_dag_dir, help=f"Root directory of final DAGs (default: {default_dag_dir})")
    parser.add_argument("--intermediate-dir", default=None, help="Path to corresponding intermediate DAGs (for fallback references in docs-index)")
    args = parser.parse_args()

    dag_dir = Path(args.dag_dir).resolve()
    intermediate_dir = Path(args.intermediate_dir).resolve() if args.intermediate_dir else None

    print("=" * 60)
    print("GENERATE L0 + DOCS-INDEX FILES (final DAGs only)")
    print("=" * 60)
    print(f"  DAG dir:       {dag_dir}")
    print(f"  Intermediate:  {intermediate_dir or 'None'}")
    print(f"  Repo name:     {get_repo_name()}")

    # Collect existing docs
    layers = collect_dag_docs(dag_dir)
    total = sum(len(v) for v in layers.values())
    print(f"\n  Found {total} docs across {len(layers)} layers:")
    for layer, docs in layers.items():
        print(f"    {layer}: {len(docs)} docs")

    # Step 1: Generate layer indexes (must happen first — L0 generation reads them)
    print("\n  Generating layer indexes...")
    for layer, docs in layers.items():
        generate_layer_index(dag_dir, layer, docs)

    # Step 2: Generate L0 primer and reading chains via LLM
    print("\n  Generating L0 primer and reading chains via LLM...")
    reading_chains_text = generate_l0_and_chains(dag_dir, layers)

    # Step 3: Generate master docs-index with LLM reading chains
    print("\n  Generating master docs-index...")
    generate_master_index(dag_dir, layers, reading_chains_text, intermediate_dir)

    print(f"\n{'='*60}")
    print("DONE")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
