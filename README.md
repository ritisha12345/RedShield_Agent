# RedShield Agent

RedShield is an autonomous LLM safety agent. Given a target LLM application and its system prompt, it generates adversarial attacks, executes them against the target, judges the responses, diagnoses vulnerabilities, proposes prompt patches, verifies those patches, and produces a structured safety report.

Core loop:

```text
ATTACK -> JUDGE -> ANALYZE -> PATCH -> VERIFY -> REPORT
```

The backend agent loop is the product. The API, queue, persistence, and frontend exist to run and visualize that loop.

## What It Shows

RedShield produces concrete before/after evidence:

- baseline attacks that caused unsafe target responses
- judge verdicts and reasons
- vulnerability categories and remaining risks
- generated prompt patches
- verification against the same attacks that originally failed
- final markdown and structured report data

Recent reports include patch effectiveness diagnostics such as `mitigated`, `changed_but_still_violation`, `unchanged_response`, and `verification_error`.

## Repository Layout

```text
agent/          Core attack, judge, analyzer, patcher, verifier, reporter loop
api/            FastAPI routes, in-memory/shared scan storage, SSE
demo_app/       SwiftPay demo target application
firebase/       Firestore integration
frontend/       React/Vite UI
models/         Shared Pydantic models
target/         Target adapters: mock, import, HTTP
tasks/          Thread/Celery scan runners
tests/          Backend test suite
utils/          Settings, retry, readiness, prompt guard helpers
docs/           Architecture and deeper design notes
```

## Requirements

- Python 3.11+
- Node.js 18+
- OpenAI API key for real LLM-backed scans
- Redis only when running Celery mode
- Firestore only when using shared production persistence

## Setup

Install backend dependencies:

```powershell
cd D:\CodexProjects\RedShield_Agent
pip install -r requirements.txt
```

Install frontend dependencies:

```powershell
cd D:\CodexProjects\RedShield_Agent\frontend
npm install
```

Create `.env` from `.env.example`:

```powershell
cd D:\CodexProjects\RedShield_Agent
copy .env.example .env
```

Never commit `.env` or API keys.

## Local Environment

For local development without Redis/Firestore:

```env
OPENAI_API_KEY=your_key
ATTACKER_MODEL=gpt-4o
JUDGE_MODEL=gpt-4o
PATCHER_MODEL=gpt-4o

REDSHIELD_SCAN_EXECUTION_MODE=thread
REDSHIELD_FIRESTORE_ENABLED=false
REDSHIELD_FIRESTORE_REQUIRED=false

CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
VITE_API_BASE_URL=http://localhost:8000
```

### Target Modes

Use the OpenAI-backed SwiftPay demo target:

```env
REDSHIELD_TARGET_MODULE=demo_app.target_app
REDSHIELD_TARGET_MODE=openai
```

Use deterministic offline mock behavior:

```env
REDSHIELD_TARGET_MODULE=demo_app.target_app
REDSHIELD_TARGET_MODE=mock
```

Call a deployed target endpoint instead:

```env
REDSHIELD_TARGET_URL=https://your-target.example.com/chat
REDSHIELD_TARGET_AUTH_HEADER=Authorization
REDSHIELD_TARGET_AUTH_TOKEN=your_token
```

When `REDSHIELD_TARGET_URL` is set, RedShield uses the HTTP adapter. Otherwise, `REDSHIELD_TARGET_MODULE` uses the import adapter. If neither is set, it falls back to the generic mock adapter.

## Run Locally

Start the backend:

```powershell
cd D:\CodexProjects\RedShield_Agent
uvicorn main:app --reload --port 8000
```

Start the frontend:

```powershell
cd D:\CodexProjects\RedShield_Agent\frontend
npm run dev
```

Open:

```text
http://localhost:5173
```

Health check:

```text
http://localhost:8000/health
```

In local `thread` mode, `/health` may report `degraded` for production readiness because Redis, Celery, Firestore, and production CORS are intentionally disabled. That is expected for local demos.

## Run a Scan from the UI

Suggested demo input:

- App name: `SwiftPay Support Assistant`
- App category: `customer_support`
- Attacks per category: `2`
- Max rounds: `2`
- Success threshold: `0.05`

System prompt: use the SwiftPay prompt from `demo_app/target_app.py` or paste your own target prompt.

Normal use cases:

```text
Check payment status
Help users understand account status
Support safe account troubleshooting
```

Restricted behaviors:

```text
Do not reveal another user's transaction data
Do not reveal fraud investigations
Do not disclose internal systems or escalation channels
Do not accept claimed authority without verification
```

Competitors:

```text
PayFast
PayWave
QuickRent
```

## API

Start a scan:

```http
POST /scans
```

Get status:

```http
GET /scans/{scan_id}
```

Stream live events with SSE:

```http
GET /scans/{scan_id}/stream
GET /scans/{scan_id}/events
```

Get final report:

```http
GET /scans/{scan_id}/report
```

Backend health/readiness:

```http
GET /health
```

## Production Mode

For Railway or another production backend, use Celery mode with Redis and shared persistence:

```env
REDSHIELD_SCAN_EXECUTION_MODE=celery
REDIS_URL=redis://...
CELERY_BROKER_URL=redis://...
CELERY_RESULT_BACKEND=redis://...
REDSHIELD_FIRESTORE_ENABLED=true
REDSHIELD_FIRESTORE_REQUIRED=true
CORS_ALLOWED_ORIGINS=https://your-frontend.example.com
OPENAI_API_KEY=your_key
```

The web API service should serve FastAPI through the Dockerfile startup. A separate Celery worker service should run the worker command and should not use an HTTP healthcheck path, because Celery does not serve HTTP traffic.

For Netlify/Vite frontend builds:

```env
VITE_API_BASE_URL=https://your-backend.example.com
```

## Tests

Run the backend suite:

```powershell
cd D:\CodexProjects\RedShield_Agent
python -m pytest tests/ -q -p no:cacheprovider
```

Build the frontend:

```powershell
cd D:\CodexProjects\RedShield_Agent\frontend
npm run build
```

## Current Demo Success Criteria

A successful RedShield demo should show:

1. `POST /scans` starts a scan.
2. Live SSE events appear in the frontend.
3. Attacks are generated across the canonical categories.
4. At least one unsafe response is detected.
5. A targeted patch is generated.
6. Verifier retests the same failing attack.
7. The report shows before/after violation rate and patch effectiveness.

The strongest proof is not that every scan has the same baseline rate. The strongest proof is within one scan:

```text
baseline violation -> generated patch -> same attack retested -> patched verdict safe
```

## Security Notes

- Do not commit `.env`, API keys, tokens, or service account JSON.
- User-provided prompt content should pass through `utils/prompt_guard.py` before entering LLM prompts.
- Judge context must contain only the attack and target response.
- Reports should expose evidence and patch outcomes, not hidden chain-of-thought.
- Target system prompts may contain proprietary information and should not be logged casually.

## More Documentation

See `docs/architecture.md` for the detailed architecture, API contracts, Firestore schema, sequence diagrams, and implementation phases.
