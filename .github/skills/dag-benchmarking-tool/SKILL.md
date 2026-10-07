# Skill: Generate an `agent-sim` DAG-readiness report for your repo

> **What this does** — Installs the **DAG Benchmarking Tool**
> (`azurebackup-dag-benchmarking`) from the internal **AzureBackup** Python feed
> and runs its `agent-sim` command, which simulates an AI coding agent
> navigating *your* repository through its own docs + navigation rules, then
> scores how well the docs let the agent answer real questions. The output is a
> JSON (and optional PDF) report with an overall score, per-persona breakdown,
> and the exact files the agent opened.

This is the full end-to-end runbook: **fresh virtual-env → credential provider →
install from the feed → run the command**. Copy-paste blocks are provided for
**Windows PowerShell** and **Linux/macOS bash**.

---

## 0. Prerequisites

| Need | Why |
|------|-----|
| **Python 3.10+** | The tool is a pure-Python package. Check: `python --version` (Windows: `py --version`). |
| **Access to the `One/AzureBackup` ADO feed** | The package is published here, not on public PyPI. You must be a member of the `msazure` org with feed read access. |
| **Azure OpenAI endpoint + key** | `agent-sim` drives a real LLM (gpt-4o) + embeddings. You need an Azure OpenAI resource with a `gpt-4o` (chat) and a `text-embedding-3-small` deployment. |
| **The target repo cloned locally** | `agent-sim` reads it from disk (read-only). It should contain the docs you want to benchmark (e.g. `copilot-docs/`, `intermediate-docs/`, `.github/copilot-instructions.md`). |

---

## 1. Create an isolated virtual environment

Keeps the tool and its dependencies off your system Python.

**PowerShell (Windows)**
```powershell
py -m venv $env:USERPROFILE\.dagbench-venv
& "$env:USERPROFILE\.dagbench-venv\Scripts\Activate.ps1"
python -m pip install --upgrade pip
```

**bash (Linux/macOS)**
```bash
python3 -m venv ~/.dagbench-venv
source ~/.dagbench-venv/bin/activate
python -m pip install --upgrade pip
```

---

## 2. Install the Azure Artifacts credential provider  ← **do not skip**

The `AzureBackup` feed is **private and authenticated**. Without the credential
provider, `pip` cannot log in and will **hang silently at
`Looking in indexes: ...`** (the #1 gotcha). Install `artifacts-keyring` from
public PyPI first:

```bash
python -m pip install --index-url https://pypi.org/simple/ artifacts-keyring
```

> On the **first** feed request the provider may pop a browser / device-code
> login. Complete it once; the token is cached for subsequent runs.

---

## 3. Install the DAG Benchmarking Tool from the AzureBackup feed

The package name on the feed is **`azurebackup-dag-benchmarking`**. It installs a
console command named **`dag-benchmarking`**.

**Recommended (fast):** pull the tool from the feed and its open-source
dependencies from public PyPI. This avoids the feed's slower PyPI-proxy path for
the big dependency tree.

```bash
python -m pip install azurebackup-dag-benchmarking ^
  --index-url https://pypi.org/simple/ ^
  --extra-index-url https://msazure.pkgs.visualstudio.com/One/_packaging/AzureBackup/pypi/simple/
```

> **PowerShell:** replace the `^` line-continuations with a backtick `` ` ``.
> **bash:** replace them with `\`.

**Alternative (feed-only):** if policy requires every dependency to come from the
feed (it has a PyPI upstream), use the feed as the single index. This is correct
but slower on first fetch:

```bash
python -m pip install azurebackup-dag-benchmarking \
  --index-url https://msazure.pkgs.visualstudio.com/One/_packaging/AzureBackup/pypi/simple/
```

Verify the install:
```bash
dag-benchmarking --version
dag-benchmarking agent-sim --help
```

---

## 4. Provide Azure OpenAI credentials

`agent-sim` reads these environment variables. **Never commit the key or paste it
into chats/logs.** Set them in your shell session only.

**PowerShell**
```powershell
$env:AZURE_OPENAI_ENDPOINT    = "https://<your-resource>.services.ai.azure.com/"
$env:AZURE_OPENAI_API_VERSION = "2024-12-01-preview"
# Type the secret yourself; do not store it in a script:
$env:AZURE_OPENAI_API_KEY     = "<your-azure-openai-key>"
```

**bash**
```bash
export AZURE_OPENAI_ENDPOINT="https://<your-resource>.services.ai.azure.com/"
export AZURE_OPENAI_API_VERSION="2024-12-01-preview"
export AZURE_OPENAI_API_KEY="<your-azure-openai-key>"
```

> The chat deployment must be named `gpt-4o` and the embedding deployment
> `text-embedding-3-small` (the tool's defaults). Override with `--chat-model`
> / `--embedding-model` if yours differ.

---

## 5. (First time only) Smoke-test with one cheap question

Confirm everything is wired before spending on a full run. **1 persona ×
1 question, hard $3 cap:**

```bash
dag-benchmarking agent-sim /path/to/your/repo \
  --personas onboarding \
  --questions-per-persona 1 \
  --concurrency 1 \
  --max-cost-usd 3 \
  --format json \
  --output dagbench-smoke \
  --verbose
```

A successful run prints `HTTP/1.1 200 OK` lines and ends with
`✓ Wrote dagbench-smoke (json)`. Open `dagbench-smoke` and check `overall_score`
and `traces[0].files_opened`.

---

## 6. Run the full report

All 10 personas × 5 questions. Emit both JSON and PDF:

```bash
dag-benchmarking agent-sim /path/to/your/repo \
  --questions-per-persona 5 \
  --concurrency 2 \
  --max-cost-usd 100 \
  --format json,pdf \
  --output dagbench-report \
  --verbose
```

This writes `dagbench-report.json` and `dagbench-report.pdf` (the literal value
of `--output` is the base path; some shells/versions emit an extensionless file
for a single format — check the `✓ Wrote ...` line).

### Useful flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--personas, -p` | all 10 | Comma-separated subset, e.g. `security_review,architecture`. |
| `--questions-per-persona, -q` | 5 | Questions per persona (1st is the canned seed task). |
| `--concurrency` | 4 | Parallel agent sessions (shared adaptive 429 throttle). |
| `--max-cost-usd` | none | Hard abort once estimated spend exceeds this. **Always set it.** |
| `--max-tool-calls` | 50 | Runaway guard per session. |
| `--answer-max-tokens` | 6000 | Completion budget per turn (prevents truncated answers). |
| `--no-nav-guide` | off | Run with **no** repo nav rules (a baseline). |
| `--format` | json | `json`, `pdf`, or `json,pdf`. |

---

## 7. Compare two doc approaches (optional)

To A/B two documentation strategies on the **same** repo, run once per variant
to separate JSON files, then diff them with the comparison script that ships in
the tool's `scripts/` folder:

```bash
dag-benchmarking agent-sim /path/to/repo-with-docs-A --format json --output runA
dag-benchmarking agent-sim /path/to/repo-with-docs-B --format json --output runB
python scripts/_compare_agentsim.py runA runB --label-a "A" --label-b "B" \
  --output comparison.md --pdf
```

---

## 8. Reading the report

| Field | Meaning |
|-------|---------|
| `overall_score` (0–100) | Mean judge score across all answers — "how good were the answers the docs enabled?" |
| `docs_index_first_rate` | % of questions where the agent opened the docs index first (a Hard Rule). |
| `tier2_before_source_rate` | When source was needed, % where the agent reached `intermediate-docs/` (tier-2) before code. |
| `by_persona` | Score per reader type (onboarding, security_review, …). |
| `traces[].files_opened` | The exact, ordered list of files the agent opened — behavioural evidence. |
| `traces[].judge.missing` | Concrete things the judge found wrong/absent (why a score dropped). |

Effort counters (tool calls, files opened, tokens, USD) are reported for
transparency and are **not** part of the score — reading more source is not
penalised.

---

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| `pip` hangs at `Looking in indexes:` | Credential provider missing — run **Step 2** (`pip install artifacts-keyring`), then retry. |
| `401`/auth loop on the feed | Token cache stale. Re-run the install; complete the device-code/browser login when prompted. |
| Feed install very slow | The feed lazily proxies PyPI. Use the **recommended** Step 3 command (PyPI primary, feed extra-index) so heavy deps come straight from PyPI. |
| `ModuleNotFoundError: dag_benchmarking` | The venv isn't activated, or the install targeted a different interpreter. Re-activate (Step 1) and reinstall. |
| `401`/`DeploymentNotFound` from Azure OpenAI | Endpoint/key/deployment names wrong. Confirm the `gpt-4o` and `text-embedding-3-small` deployments exist, or pass `--chat-model` / `--embedding-model`. |
| Run aborts with a cost message | `--max-cost-usd` cap hit — expected guardrail. Raise it or reduce `-q`/personas. |

---

## Security notes

- The `AZURE_OPENAI_API_KEY` is a **secret**. Set it only as an environment
  variable in your session. Do **not** commit it, echo it, or paste it into
  chats, PRs, or logs. If it is ever exposed, **rotate it** in the Azure portal.
- The tool reads target repos **read-only**; it never writes to or mutates the
  repo it benchmarks.
