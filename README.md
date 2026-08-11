# Defender — AI Code Compliance Defender for Banking

**Defender** is an AI-powered code validation and governance platform built for
regulated financial systems. It audits, validates, and governs both
human-written and **AI-generated** code *before it reaches production* — running
on every pull request and checking your diff against multiple quality layers.

Built on the **genuine Google Agent Development Kit (ADK)** — real
`LlmAgent`/`ParallelAgent`/`Runner` orchestration, not an "ADK-style" imitation
— with a **Bring-Your-Own-Model (BYOM)** design so it can run fully on-premise /
air-gapped for regulated workloads. It ships with an **offline deterministic
mock model** so it runs with **zero API keys** today, and a **product showcase
website** with a live interactive demo (`defender serve`).

> Think of it as a *Defender* system: shift-left agentic evaluation that catches
> logic flaws, architectural erosion, security vulnerabilities, and compliance
> violations early — with reproducible, audit-defensible findings.

---

## Core capabilities

| Capability | What it does |
| --- | --- |
| **Continuous validation** | Reviews PRs / MRs automatically across 6 quality layers. |
| **Shift-left agentic evaluation** | Multi-model LLM orchestration + static analysis to catch issues early in the SDLC. |
| **Enterprise governance** | Validates against PCI-DSS, SOC 2, GDPR, HIPAA + a configurable gate policy. |
| **Flexible deployment (BYOM)** | Gemini (Google ADK), OpenAI-compatible, on-prem Ollama, or offline mock. |
| **Developer workflow integrations** | CLI, web dashboard, GitHub App webhook, GitLab webhook, JSON API. |

### The six quality layers (analyzer agents)

1. **Security / SAST** — secrets, injection, weak crypto, TLS misconfig, deserialization.
2. **Compliance** — PCI-DSS (PAN/CVV), SOC 2, GDPR/PII, HIPAA.
3. **Quality** — DRY/SOLID, error handling, maintainability.
4. **Performance** — N+1 queries, blocking I/O, inefficient access.
5. **Architecture** — layering violations, coupling, global state.
6. **Vulnerability** — vulnerable dependency usage, insecure randomness, missing timeouts.

Each agent fuses **deterministic static rules** (fast, reproducible, auditable)
with **LLM contextual reasoning** via the configured model backend.

---

## Architecture

```
                       ┌──────────────────────────────────────┐
   PR / MR / CLI / API │              Defender                 │
   ───────────────────▶│  diff parser ─▶ Orchestrator          │
                       │                   │ (runs agents in    │
                       │                   │  parallel)         │
                       │   ┌───────────────┴───────────────┐    │
                       │   ▼   ▼   ▼   ▼   ▼   ▼            │    │
                       │  SEC CMP QUAL PERF ARCH VULN agents │    │
                       │   │ (static rules + BYOM model)     │    │
                       │   └───────────────┬───────────────┘    │
                       │        scoring + gate policy           │
                       │                   │                    │
                       │   ComplianceReport ▶ JSON/SARIF/MD/HTML │
                       └──────────────────────────────────────┘
```

Key modules:

- `defender/core/` — domain models, config, diff parser.
- `defender/models/` — **BYOM** provider abstraction (mock / gemini+ADK / openai / ollama).
- `defender/rules/` — deterministic static rule catalogs.
- `defender/agents/` — analyzer agents (one per dimension).
- `defender/scoring.py` — score + gate policy (the governance brain).
- `defender/engine.py` — the multi-agent orchestrator.
- `defender/reporting/` — JSON / SARIF / Markdown / HTML renderers.
- `defender/cli.py` — the CLI.
- `defender/web/` — FastAPI dashboard + webhook receivers.
- `defender/integrations/` — GitHub / GitLab plumbing.

---

## Quickstart

```bash
# 1. Create the environment & install (uses offline mock model by default)
uv venv --python 3.13
uv pip install -e ".[dev]"

# 2. Scan the intentionally-vulnerable sample
defender scan examples/vulnerable_payment.py

# 3. Scan a whole directory or audit an entire repo (respects .gitignore)
defender scan src/
defender audit .                     # full-repo compliance audit

# 4. Review a diff (PR-style)
git diff origin/main | defender review --stdin

# 5. Launch the dashboard + webhook receiver
defender serve            # http://127.0.0.1:8100
```

### Working across whole repos / git repos

| Command | What it does |
| --- | --- |
| `defender scan <files or dirs>` | Expands directories, respects `.gitignore`, skips vendor/build/binary/oversized files. |
| `defender audit <repo root>` | Full-repository compliance audit. |
| `defender review --git <ref>` | Reviews the diff of a git range (the PR-review path). |
| `--llm-max-files N` | Caps how many files go to the LLM (static rules always cover **every** file). |
| `--no-gitignore` | Walk everything, ignore `.gitignore`. |

Large codebases degrade predictably: **static analysis covers every file**, and
the LLM analyzes up to `--llm-max-files` across multiple batched calls so nothing
is silently truncated. The report notes when a file-count cap was hit.

The CLI exits non-zero when the gate **FAILs**, so it drops straight into CI:

```bash
defender review --git origin/main --format sarif -o defender.sarif || exit 1
```

---

## BYOM configuration

Copy `.env.example` to `.env` and choose a provider:

```ini
DEFENDER_MODEL_PROVIDER=mock      # mock | gemini | openai | ollama
DEFENDER_MODEL_NAME=gemini-2.0-flash
```

- **mock** — deterministic, offline, zero keys. Great for CI + fast tests.
- **adk** — **genuine Google ADK**: real `LlmAgent`s under a `ParallelAgent` +
  `Runner`. Model calls route through a custom `BaseLlm` (`GatewayLlm`) to your
  BYOM backend. `pip install ".[gemini]"`; requires `google-adk`.
- **gateway** — direct Gemini via the Walmart PROD LLM Gateway (no ADK).
- **gemini** — Google ADK's raw `LlmAgent` against public Gemini/Vertex. Set `GOOGLE_API_KEY`.
- **openai** — any OpenAI-compatible endpoint. Set `OPENAI_API_KEY` / `OPENAI_BASE_URL`.
  **This one has automatic precedence**: if `OPENAI_API_KEY` (or the `OPENAIKEY`
  shorthand) is set *at all*, Defender uses it regardless of
  `DEFENDER_MODEL_PROVIDER` — the Walmart Gateway/ADK/Gemini path is switched
  off automatically. See [GETTING_STARTED.md](GETTING_STARTED.md) for details.
- **ollama** — on-prem / air-gapped. Set `OLLAMA_BASE_URL` / `OLLAMA_MODEL`.

If a real provider's dependency or key is missing, Defender **degrades to the
mock provider** rather than crashing, and says so in the report.

---

## Gate policy (governance)

```ini
DEFENDER_GATE_MIN_SCORE=80        # minimum overall score to PASS
DEFENDER_GATE_BLOCK_SEVERITY=high # block PR if any finding >= this severity
```

Verdicts: **PASS** / **WARN** / **FAIL**. Security & compliance dimensions are
weighted more heavily in the overall score.

---

## CI/CD integration

See `examples/ci/` for ready-to-use:

- `github-actions.yml` — runs Defender on every PR, uploads SARIF.
- `gitlab-ci.yml` — runs Defender as a merge-request job.

Or point a **GitHub App / GitLab webhook** at the running service:

- `POST /webhook/github`
- `POST /webhook/gitlab`

Each automatically diff-reviews every PR/MR (`opened`/`synchronize`/`update`) and
posts the verdict back as a comment + commit status. In addition, commenting
**`/defender audit`** on an open PR/MR triggers an on-demand **full-repository**
audit of that branch (shallow-clone — not just the diff), posted as a follow-up
comment. Useful when a change's *blast radius* matters more than the diff itself
(e.g. a dependency bump, a shared-util refactor, or a pre-release sanity check).

---

## Product showcase website

`defender serve` launches a full marketing/demo site at `http://127.0.0.1:8100`:

- **Landing page** — hero, six-agent feature grid, the real ADK architecture
  diagram, compliance frameworks, and CI/CD integration snippets.
- **Live interactive demo** — paste code or a diff, run it through the real
  engine (static rules + your configured BYOM backend), see the score ring,
  per-dimension breakdown, and findings render instantly via HTMX.
- **Full HTML report** (`/report/<id>`) — shareable, printable, dark-themed.

---

## Running tests

```bash
pytest
```

---

## License

Proprietary — internal banking tooling.
# code-defender
