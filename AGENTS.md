# AGENTS.md — RedShield

## PROJECT OVERVIEW

RedShield is an autonomous LLM safety agent.

Given a target LLM application and its system prompt, RedShield:

1. Generates adversarial attacks
2. Executes attacks against the target
3. Judges responses for safety violations
4. Diagnoses vulnerability patterns
5. Proposes prompt patches
6. Verifies patch effectiveness
7. Produces a structured safety report

Core loop:

```text
ATTACK → JUDGE → ANALYZE → PATCH → VERIFY → REPORT
```

The backend agent loop is the product.

The API, database, queue, and frontend exist only to expose and visualize the loop.

Detailed architecture, API contracts, Firestore schema, demo specification, and design rationale live in `/docs`.

---

# ENGINEERING PRINCIPLES

## Principle 1 — Core Loop First

Never prioritize UI, authentication, analytics, dashboards, or infrastructure over the agent loop.

The first milestone is:

```text
attacker → target → judge → result
```

running successfully from the terminal.

If the loop does not work, the product does not exist.

---

## Principle 2 — Backend Over Frontend

This project is backend-first.

Keep frontend minimal.

Frontend responsibilities:

* collect scan input
* display live activity
* display report

Do not introduce complex frontend state management or unnecessary UI abstractions.

---

## Principle 3 — Build the Simplest Working Version

Prefer:

```text
working > elegant
simple > flexible
implemented > planned
```

Avoid speculative abstractions.

Do not build infrastructure for future requirements that do not yet exist.

---

# REPOSITORY STRUCTURE

```text
redshield/

agent/          Core agent implementation
api/            FastAPI route handlers
models/         Shared Pydantic models
tasks/          Celery tasks
target/         Demo target applications
firebase/       Firestore and Auth integration
utils/          Shared utilities
frontend/       React frontend
tests/          Test suite
docs/           Architecture and specifications

main.py         FastAPI entrypoint
worker.py       Celery worker entrypoint
```

New files should be placed in the correct directory.

Do not create duplicate functionality across directories.

---

# ENVIRONMENT SETUP

## Backend

```bash
pip install -r requirements.txt
```

## Frontend

```bash
cd frontend
npm install
```

## Environment Variables

Create:

```text
.env
```

from:

```text
.env.example
```

Never commit secrets.

---

# RUN COMMANDS

Start services in this order.

## Terminal 1

```bash
redis-server
```

## Terminal 2

```bash
celery -A worker worker --loglevel=info
```

## Terminal 3

```bash
uvicorn main:app --reload --port 8000
```

## Terminal 4

```bash
cd frontend
npm run dev
```

---

# TEST COMMANDS

Run all tests:

```bash
pytest tests/ -v
```

Run a specific test:

```bash
pytest tests/test_judge.py -v
```

---

# SECURITY RULES

These rules are mandatory.

## User Content Isolation

All user-provided content entering an LLM prompt must pass through:

```text
utils/prompt_guard.py
```

Never insert raw user input directly into prompts.

---

## Secret Management

Never hardcode:

* API keys
* tokens
* credentials
* secrets

Use environment variables only.

---

## Sensitive Prompt Handling

User system prompts may contain proprietary information.

Never:

* log system prompts
* expose system prompts in error messages
* expose system prompts in reports without explicit intent

---

## Judge Isolation

Judge context must contain:

* attack
* target response

Judge context must never contain:

* attacker reasoning
* attacker chain-of-thought
* attacker system prompts
* previous internal reasoning

---

# CODE CONVENTIONS

## Python

* Python 3.11+
* Type hints required
* Use Pydantic models for structured data
* Functions must have docstrings

## Naming

```text
Classes      PascalCase
Functions    snake_case
Constants    UPPER_SNAKE_CASE
```

## LLM Calls

Judge:

```python
temperature=0
```

Attacker:

```python
temperature=0.8
```

Always:

* specify max_tokens
* use retry logic
* return structured output

All LLM calls must go through:

```text
utils/retry.py
```

---

# CANONICAL VULNERABILITY CATEGORIES

These values are authoritative.

```python
VULNERABILITY_CATEGORIES = [
    "jailbreak",
    "roleplay",
    "authority",
    "hypothetical",
    "escalation",
    "pii_extraction",
    "competitor_bypass",
    "prompt_override",
]
```

Any mismatch between:

* attacker
* judge
* analyzer
* verifier
* reports
* models

is a bug.

---

# DEFINITION OF DONE

## attacker.py

Done when:

* attacks span all vulnerability categories
* output is structured
* user content is isolated correctly

---

## judge.py

Done when:

* output is valid structured JSON
* known violations are correctly identified
* attacker reasoning is never visible

---

## orchestrator.py

Done when:

* full loop executes automatically
* success and failure termination paths work
* errors are handled gracefully

---

## patcher.py

Done when:

* patches target specific vulnerabilities
* normal chatbot behavior remains intact

---

## verifier.py

Done when:

* only successful attacks are re-tested
* results are structured and reproducible

---

## Full System

Done when:

```text
POST /scans
        ↓
scan starts
        ↓
live events stream
        ↓
report generated
```

without manual intervention.

---

# PRIORITY ORDER

Build in this order.

## Phase 1 — Core Intelligence

1. attacker.py
2. judge.py
3. orchestrator.py

Goal:

```text
attacker → target → judge
```

working in terminal.

---

## Phase 2 — Safety Improvement Loop

4. analyzer.py
5. patcher.py
6. verifier.py

Goal:

```text
attack
→ judge
→ patch
→ verify
```

working end-to-end.

---

## Phase 3 — API Layer

7. POST /scans
8. scan status endpoint
9. SSE event stream

---

## Phase 4 — Frontend

10. setup page
11. live activity feed
12. report page

Keep frontend minimal.

---

## Phase 5 — Optional Hardening

Only after the demo works:

* authentication
* rate limiting
* usage tracking
* historical reports
* multi-user support

Do not implement optional hardening before Phase 4 is complete.

---

# DEMO SUCCESS CRITERIA

A successful demo can:

1. Accept a target system prompt
2. Launch a scan
3. Generate attacks
4. Detect violations
5. Propose patches
6. Verify improvements
7. Display before/after results

A measurable reduction in violation rate is the primary success metric.

---

# WHEN UNSURE

Prefer the solution that:

* keeps the agent loop simple
* reduces complexity
* increases reliability
* improves demoability

The shortest path to a working autonomous safety agent is usually the correct path.