# Getting Started with Defender

This is the practical, step-by-step guide: what you need before you start,
how to install it, how to run it, and how to configure a model backend
(including bringing your own OpenAI key). For the product pitch and
architecture deep-dive, see [README.md](README.md).

---

## 1. Prerequisites

| Requirement | Why | Check it |
| --- | --- | --- |
| **Python 3.11+** (3.13 recommended) | Defender's runtime | `python3 --version` |
| **`uv`** (Python packager) | Fast venv + install, this project's standard tool | `uv --version` |
| **`git`** | Needed for `defender audit <git-url>` and `defender review --git` | `git --version` |
| A model backend *(optional)* | LLM-powered findings on top of static rules | see [Section 4](#4-choose-a-model-backend-byom) |

Don't have `uv`? Install it first:

```bash
brew install uv          # macOS
# or, Windows/Linux:
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**You do not need any API key to try Defender.** It ships with an offline,
deterministic **mock** model backend so static analysis + the full CLI/web
experience work with zero signup, zero network calls, zero cost.

---

## 2. Install

```bash
git clone <this-repo-url> defender
cd defender

# Create a virtual environment and install (editable, with dev tools)
uv venv --python 3.13
source .venv/bin/activate        # Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"
```

Verify the install:

```bash
defender --help
```

---

## 3. Run it

### Option A — CLI, scan a file or directory

```bash
# Scan the intentionally-vulnerable sample bundled with the repo
defender scan examples/vulnerable_payment.py

# Scan a whole directory (respects .gitignore, skips vendor/binary/oversized)
defender scan src/

# Full-repository compliance audit -- local path OR a public git URL
defender audit .
defender audit https://github.com/pallets/itsdangerous
```

The CLI exits **non-zero** when the compliance gate FAILs, so it drops
straight into any CI pipeline:

```bash
defender review --git origin/main --format sarif -o defender.sarif || exit 1
```

### Option B — Review a PR-style diff

```bash
git diff origin/main | defender review --stdin
```

### Option C — Website + live demo + webhooks

```bash
defender serve            # http://127.0.0.1:8100
```

This launches:

- A **product showcase landing page** (architecture, compliance frameworks,
  CI/CD snippets).
- A **live interactive demo** — paste code/a diff, or point it at a public
  repo URL, and watch it run through the *real* engine with a live,
  stage-by-stage progress panel (connect → clone → scan → static rules →
  dispatch to agents → score).
- **Webhook receivers** for GitHub (`POST /webhook/github`) and GitLab
  (`POST /webhook/gitlab`) that auto-review every PR/MR, plus an on-demand
  `/defender audit` comment trigger for a full-repo audit.
- A **JSON API** (`POST /api/analyze`) for IDE/tooling integration.

---

## 4. Choose a model backend (BYOM)

Static rules always run — deterministic, fast, zero config. The **LLM layer**
on top is optional and pluggable (Bring-Your-Own-Model). Copy the example
config and pick one:

```bash
cp .env.example .env
```

| Provider | Set `DEFENDER_MODEL_PROVIDER=` | What you also need |
| --- | --- | --- |
| **mock** *(default)* | `mock` | Nothing. Offline, deterministic, zero keys. |
| **openai** | `openai` *(or just set the key — see below)* | `OPENAI_API_KEY` |
| **adk** | `adk` | `google-adk` installed + a configured gateway/Gemini backend |
| **gemini** | `gemini` | `GOOGLE_API_KEY` |
| **ollama** | `ollama` | A local/on-prem Ollama server |

### Bring your own OpenAI key (recommended for external use)

Just export the key — **no other configuration change needed**:

```bash
export OPENAI_API_KEY=sk-...
# or, the shorthand also works:
export OPENAIKEY=sk-...
```

**Precedence rule:** if an OpenAI key is present *at all* (via either env var
name above, or in `.env`), Defender automatically routes every LLM call
through OpenAI.
This means you can safely leave the rest of `.env` untouched (e.g. still
pointed at `adk`/`gateway` for internal use) and just export the key when you
want to run externally on your own OpenAI account instead.

Optional tuning:

```bash
export OPENAI_MODEL=gpt-4o-mini        # default; any chat-completions model works
export OPENAI_BASE_URL=https://api.openai.com/v1   # or any OpenAI-compatible proxy
```

Verify which backend is actually active:

```bash
defender serve &
curl -s http://127.0.0.1:8100/healthz
# {"status":"ok","provider":"openai","configured_provider":"mock"}
```

`provider` is what's actually running (after key precedence);
`configured_provider` is the raw `DEFENDER_MODEL_PROVIDER` value, shown so
you can tell at a glance when the OpenAI-key override kicked in.

If a real provider's dependency or key is missing/invalid, Defender
**degrades to the mock provider** rather than crashing, and says so in the
report — a compliance gate should never go down because a key expired.

---

## 5. Governance / gate policy

```ini
DEFENDER_GATE_MIN_SCORE=80        # minimum overall score (0-100) to PASS
DEFENDER_GATE_BLOCK_SEVERITY=high # block if any finding >= this severity
```

Verdicts are **PASS** / **WARN** / **FAIL**. Security & compliance dimensions
are weighted more heavily in the overall score — see `defender/scoring.py`.

---

## 6. Run the tests

```bash
pytest
```

All tests run against the **mock** provider by default (see
`tests/conftest.py`), so they're fast and require no network access or API
keys.

---

## 7. Common gotchas

- **"No files were analyzed" / a suspicious PASS on an empty scan** — this is
  a deliberate loud warning, not a bug: a 0-file scan with a PASS verdict
  would otherwise be a silent false-green. Check your path/URL and
  `.gitignore` rules.
- **Unfamiliar language in your repo scans to 0 files** — `defender/core/repo.py`
  has a broad but finite extension allowlist. If your stack isn't covered,
  add the extension there (PRs welcome).
- **Website checkbox for "Use AI agents" seems to do nothing** — if you're on
  an old checkout, update: this was a real bug (browsers omit unchecked
  checkboxes entirely, which used to fall through to FastAPI's default). Fixed
  via a hidden-fallback-field pattern in `demo.html`.

---

## Where to go next

- [README.md](README.md) — architecture, the six analyzer agents, CI/CD
  integration examples.
- `examples/ci/` — ready-to-use GitHub Actions / GitLab CI snippets.
- `defender/core/config.py` — the full list of tunable settings.
