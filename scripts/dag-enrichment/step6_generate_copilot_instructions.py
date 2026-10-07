"""
Generate `.github/copilot-instructions.md` from the final DAG documentation.

Reads:
  1. {dag_dir}/L0-foundations/codebase-primer.md  — architecture, terminology, ownership
  2. {dag_dir}/docs-index.md                       — master index + reading chains
  3. {dag_dir}/L1-conceptual/docs-index.md         — L1 doc list + descriptions
  4. {dag_dir}/L2-platform/docs-index.md           — L2 doc list + descriptions
  5. {dag_dir}/L3-flows/docs-index.md              — L3 doc list + descriptions

Calls the LLM once to synthesize a repo-specific `copilot-instructions.md` that contains:
  - Brief codebase description (1 paragraph)
  - Documentation section linking to L0 primer + master/layer indexes
  - Ownership Table (Topic | Code Area | Doc Area) mapping high-level concerns
    to source paths and the matching DAG docs
  - Hard Rules — invariants AI agents must follow (always read L0 first,
    consult docs before searching code, preserve serialization compatibility, etc.)
  - Build & Test — standard build/test commands (best-effort from repo signals,
    or placeholders for the user to fill in)
  - Code Conventions — naming, suffixes, mocking, test framework conventions

Writes the output to:
  - `.github/copilot-instructions.md`  (if it does not exist)
  - `.github/copilot-instructions-dag.md`  (if `.github/copilot-instructions.md` already exists)

This script runs after `generate_indexes_and_l0.py` (which produces the L0 primer
and the docs-index files this script consumes).

Usage:
    python scripts/dag-enrichment/step6_generate_copilot_instructions.py \
        --dag-dir copilot-docs

    python scripts/dag-enrichment/step6_generate_copilot_instructions.py \
        --dag-dir copilot-docs --github-dir .github --force-suffix
"""

import argparse
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
LOG_DIR = Path(__file__).resolve().parent / "output" / "enrichment-logs"

DEFAULT_OUTPUT_NAME = "copilot-instructions.md"
ALT_OUTPUT_NAME = "copilot-instructions-dag.md"


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


def read_if_exists(path: Path) -> str:
    """Return file contents if it exists, else empty string."""
    if path.exists():
        try:
            return path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"    WARNING: Could not read {path}: {e}")
    return ""


def detect_repo_signals(repo_root: Path) -> dict:
    """Best-effort detection of build/test signals to seed the Build & Test section."""
    signals = {
        "has_dotnet": False,
        "has_node": False,
        "has_python": False,
        "has_go": False,
        "has_rust": False,
        "has_maven": False,
        "has_gradle": False,
        "has_make": False,
        "build_files": [],
    }

    indicators = {
        "has_dotnet":  ["*.sln", "dirs.proj", "Directory.Build.props", "global.json"],
        "has_node":    ["package.json"],
        "has_python":  ["pyproject.toml", "setup.py", "requirements.txt"],
        "has_go":      ["go.mod"],
        "has_rust":    ["Cargo.toml"],
        "has_maven":   ["pom.xml"],
        "has_gradle":  ["build.gradle", "build.gradle.kts"],
        "has_make":    ["Makefile"],
    }

    for key, patterns in indicators.items():
        for pat in patterns:
            matches = list(repo_root.glob(pat))
            if matches:
                signals[key] = True
                signals["build_files"].extend(str(m.relative_to(repo_root)).replace("\\", "/")
                                              for m in matches[:3])
                break

    # Also look for init scripts at the root (common Microsoft repo pattern)
    for script in ["init.sh", "init.ps1", "initWindows.cmd", "initLinux.cmd"]:
        if (repo_root / script).exists():
            signals["build_files"].append(script)

    # Deduplicate while preserving order
    seen = set()
    signals["build_files"] = [f for f in signals["build_files"] if not (f in seen or seen.add(f))]
    return signals


def build_layer_index_context(dag_dir: Path) -> str:
    """Concatenate the per-layer docs-index.md files as LLM context."""
    parts = []
    for layer in ["L1-conceptual", "L2-platform", "L3-flows"]:
        index_file = dag_dir / layer / "docs-index.md"
        if index_file.exists():
            content = index_file.read_text(encoding="utf-8")
            parts.append(f"=== {layer}/docs-index.md ===\n{content}")
    return "\n\n".join(parts)


def determine_output_path(github_dir: Path, force_suffix: bool) -> Path:
    """
    Decide where to write the generated instructions.

    - If `--force-suffix` is set, always write to copilot-instructions-dag.md.
    - Else if .github/copilot-instructions.md already exists, write to copilot-instructions-dag.md.
    - Else write to .github/copilot-instructions.md.
    """
    primary = github_dir / DEFAULT_OUTPUT_NAME
    alternate = github_dir / ALT_OUTPUT_NAME
    if force_suffix:
        return alternate
    if primary.exists():
        return alternate
    return primary


def build_prompt(repo_name: str, l0_content: str, master_index_content: str,
                 layer_index_content: str, signals: dict) -> str:
    """Build the LLM prompt for generating copilot-instructions.md."""
    build_signals_text = "\n".join(f"  - {k}: {v}" for k, v in signals.items()
                                   if k != "build_files")
    build_files_text = "\n".join(f"  - {f}" for f in signals["build_files"]) or "  (none detected)"

    return f"""You are generating a `copilot-instructions.md` file for the repository "{repo_name}".

This file lives at `.github/copilot-instructions.md` and is loaded into every AI agent
session. It tells the agent HOW to navigate this codebase: where docs live, what rules
to follow, build/test commands, and code conventions.

## CONTEXT 1 — L0 Foundation Primer (codebase architecture)
{l0_content if l0_content else '(no L0 primer found)'}

## CONTEXT 2 — Master docs-index.md (DAG documentation map)
{master_index_content if master_index_content else '(no master docs-index found)'}

## CONTEXT 3 — Per-layer docs-index files (DAG document inventory)
{layer_index_content if layer_index_content else '(no layer indexes found)'}

## CONTEXT 4 — Repo build signals (best-effort heuristics)
Detected build systems:
{build_signals_text}
Detected root build files:
{build_files_text}

## YOUR TASK
Generate the FULL contents of `copilot-instructions.md`. The file is loaded into every
agent session, so it MUST be concise and dense. Target 80–140 lines.

## REQUIRED STRUCTURE (in this exact order)

# {repo_name}

<one short paragraph — 1 to 3 sentences — describing what this codebase is and does.
Synthesize from the L0 primer's Architecture section. Do not invent capabilities.>

## Documentation

MUST read the documentation index before searching code for any non-trivial task:

- [Master docs-index](../copilot-docs/docs-index.md) — Start here. Contains layer indexes and reading chains.
- [L0 Primer](../copilot-docs/L0-foundations/codebase-primer.md) — Always-loaded architecture foundation.
- [L1 Conceptual Index](../copilot-docs/L1-conceptual/docs-index.md) — <one-line summary of what L1 covers, derived from the layer's docs>.
- [L2 Platform Index](../copilot-docs/L2-platform/docs-index.md) — <one-line summary of what L2 covers, derived from the layer's docs>.
- [L3 Flows Index](../copilot-docs/L3-flows/docs-index.md) — <one-line summary of what L3 covers, derived from the layer's docs>.

## Ownership Table

A Markdown table with columns: Topic | Code Area | Doc Area
- Pick 8–14 of the most important topics from the L0 primer's "Key Components" /
  "Ownership Map" tables and from the L1/L2/L3 doc descriptions.
- "Code Area" should be the source-tree path that owns the topic (e.g.,
  `src/Foo/Bar/`). Derive these from the L0 primer if it lists them; otherwise
  leave the cell as `(see docs)`.
- "Doc Area" must reference an actual DAG doc by name (e.g.,
  `L1 fsm-framework.md` or `L3 backup-flow.md`). Use only doc names that
  appear in the layer indexes above.

## Hard Rules

A Markdown bulleted list. Always include these baseline rules (rephrased to fit
the repo's terminology where appropriate):
- MUST read `copilot-docs/docs-index.md` before searching code for architecture,
  flow, or design questions.
- MUST read the L0 primer before answering any architecture question.
- Context resolution order — When a final DAG doc in `copilot-docs/` does not
  provide enough detail, MUST read the corresponding detailed content file at
  `intermediate-docs/{{layer}}/{{name}}.content.md` BEFORE searching source code.
  Only go to source code if BOTH the compact DAG doc AND the detailed content
  file are insufficient. Include a worked example mapping
  `copilot-docs/L1-conceptual/<example>.md` → `intermediate-docs/L1-conceptual/<example>.content.md`
  using a real doc name from the layer indexes above.
- Then add 2–4 ADDITIONAL repo-specific rules synthesized from the L0 primer
  (e.g., serialization-compatibility rules, cross-platform .cs / .Windows.cs /
  .Linux.cs trio rules, FSM Block discipline, dependency direction rules).
  ONLY add rules that are clearly supported by the L0 primer or layer
  indexes — do NOT invent rules.

## Build & Test

A short section with:
- A "Targets:" line summarizing platforms / runtimes if obvious from the L0 primer
  or detected build signals (e.g., "Targets: net8.0 (Linux) | net462 (Windows)").
  If unknown, omit this line.
- A fenced bash block with the most likely build and test commands based on the
  detected build signals. Examples:
    * .NET: `dotnet restore`, `dotnet build`, `dotnet test`
    * Node:  `npm install`, `npm run build`, `npm test`
    * Python: `pip install -r requirements.txt`, `pytest`
    * Maven: `mvn -B verify`
    * Gradle: `./gradlew build test`
    * Make:  `make`, `make test`
  Include any detected init scripts (init.sh / init.ps1 / initWindows.cmd /
  initLinux.cmd) before the build commands when present.
- If no build system was detected, write a single line:
  `> Build and test commands are repo-specific. Fill in for this codebase.`
  followed by an empty fenced bash block.

## Code Conventions

A Markdown bulleted list of 4–8 conventions inferred from the L0 primer or layer
indexes (e.g., interface naming, suffix conventions, serialization library,
test framework, mocking library, feature-flag system). DO NOT invent
conventions that are not supported by the context. If the context is too thin,
write a single bullet: `- Conventions to be documented as the codebase matures.`

## OUTPUT RULES
- Output ONLY the Markdown content of `copilot-instructions.md`.
- No markdown code fences around the whole output.
- No preamble, no explanation, no trailing notes.
- Do not include placeholder angle-brackets like `<...>` in the final output —
  every section must contain real content derived from the context.
- If a section truly has no information, write a single sentence saying so
  rather than leaving it empty.
"""


def write_minimal_fallback(output_file: Path, repo_name: str, signals: dict):
    """Write a minimal copilot-instructions.md when the LLM call fails."""
    lines = [
        f"# {repo_name}",
        "",
        f"Repository-specific instructions for AI agents working in `{repo_name}`.",
        "",
        "## Documentation",
        "",
        "MUST read the documentation index before searching code for any non-trivial task:",
        "",
        "- [Master docs-index](../copilot-docs/docs-index.md) — Start here.",
        "- [L0 Primer](../copilot-docs/L0-foundations/codebase-primer.md) — Always-loaded architecture foundation.",
        "- [L1 Conceptual Index](../copilot-docs/L1-conceptual/docs-index.md)",
        "- [L2 Platform Index](../copilot-docs/L2-platform/docs-index.md)",
        "- [L3 Flows Index](../copilot-docs/L3-flows/docs-index.md)",
        "",
        "## Hard Rules",
        "",
        "- MUST read `copilot-docs/docs-index.md` before searching code for architecture, flow, or design questions.",
        "- MUST read the L0 primer before answering any architecture question.",
        "- When a compact DAG doc lacks detail, read `intermediate-docs/{layer}/{name}.content.md` before searching source code.",
        "",
        "## Build & Test",
        "",
        "> Build and test commands are repo-specific. Fill in for this codebase.",
        "",
        "```bash",
        "```",
        "",
        "## Code Conventions",
        "",
        "- Conventions to be documented as the codebase matures.",
        "",
    ]
    output_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"    Created (minimal fallback): {output_file.relative_to(REPO_ROOT)} ({len(lines)} lines)")


def strip_code_fences(text: str) -> str:
    """Strip a single wrapping ```...``` fence if the LLM added one."""
    text = text.strip()
    fence = re.match(r'^```(?:\w+)?\s*\n([\s\S]*?)\n```\s*$', text)
    if fence:
        return fence.group(1).strip()
    return text


def main():
    parser = argparse.ArgumentParser(
        description="Generate .github/copilot-instructions.md from final DAG docs"
    )
    default_dag_dir = str(REPO_ROOT / "copilot-docs")
    default_github_dir = str(REPO_ROOT / ".github")
    parser.add_argument("--dag-dir", default=default_dag_dir,
                        help=f"Root directory of final DAGs (default: {default_dag_dir})")
    parser.add_argument("--github-dir", default=default_github_dir,
                        help=f"Output .github directory (default: {default_github_dir})")
    parser.add_argument("--force-suffix", action="store_true",
                        help="Always write to copilot-instructions-dag.md, even if "
                             "the primary file does not exist.")
    args = parser.parse_args()

    dag_dir = Path(args.dag_dir).resolve()
    github_dir = Path(args.github_dir).resolve()
    github_dir.mkdir(parents=True, exist_ok=True)

    repo_name = get_repo_name()
    output_file = determine_output_path(github_dir, args.force_suffix)

    print("=" * 60)
    print("GENERATE .github/copilot-instructions.md")
    print("=" * 60)
    print(f"  DAG dir:     {dag_dir}")
    print(f"  GitHub dir:  {github_dir}")
    print(f"  Repo name:   {repo_name}")
    print(f"  Output file: {output_file.relative_to(REPO_ROOT)}")
    if output_file.name == ALT_OUTPUT_NAME and not args.force_suffix:
        print(f"  (using {ALT_OUTPUT_NAME} because {DEFAULT_OUTPUT_NAME} already exists)")

    # Gather context
    l0_file = dag_dir / "L0-foundations" / "codebase-primer.md"
    master_index_file = dag_dir / "docs-index.md"

    l0_content = read_if_exists(l0_file)
    master_index_content = read_if_exists(master_index_file)
    layer_index_content = build_layer_index_context(dag_dir)
    signals = detect_repo_signals(REPO_ROOT)

    print(f"\n  L0 primer:        {'found' if l0_content else 'MISSING'} "
          f"({len(l0_content)} chars)")
    print(f"  Master index:     {'found' if master_index_content else 'MISSING'} "
          f"({len(master_index_content)} chars)")
    print(f"  Layer indexes:    {'found' if layer_index_content else 'MISSING'} "
          f"({len(layer_index_content)} chars)")
    detected = [k.removeprefix('has_') for k, v in signals.items()
                if k.startswith('has_') and v]
    print(f"  Build signals:    {', '.join(detected) if detected else 'none'}")

    if not (l0_content or master_index_content or layer_index_content):
        print("\n  WARNING: No DAG documentation context found. "
              "Run generate_indexes_and_l0.py first.")
        write_minimal_fallback(output_file, repo_name, signals)
        return

    # Build prompt and call LLM
    prompt = build_prompt(repo_name, l0_content, master_index_content,
                          layer_index_content, signals)

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    result_file = LOG_DIR / "_copilot_instructions_result.md"

    print("\n  Calling LLM to generate copilot-instructions.md...")
    result = call_copilot_cli(prompt, result_file)

    if not result:
        print("    WARNING: LLM call failed — falling back to minimal template.")
        write_minimal_fallback(output_file, repo_name, signals)
        return

    cleaned = strip_code_fences(result)
    output_file.write_text(cleaned.rstrip() + "\n", encoding="utf-8")
    line_count = len(cleaned.split("\n"))
    print(f"    Created: {output_file.relative_to(REPO_ROOT)} ({line_count} lines)")

    print(f"\n{'='*60}")
    print("DONE")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
