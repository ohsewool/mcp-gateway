# Repository Instructions: MCP Security & Reliability Gateway

## Mission

Build and evaluate an MCP-aware proxy gateway at the host boundary that improves the security, authorization control, reliability, and auditability of MCP tool usage.

## Authority and scope

- `docs/PROJECT_SPEC.md` is the approved scope baseline.
- Deterministic policy enforcement is the authoritative control. Heuristic or LLM-derived risk signals, if separately approved, may only be non-authoritative secondary signals.
- Use isolated MCP servers (synthetic fixtures, or open-source server implementations launched locally in this sandbox), synthetic data, and mock credentials. Real protocol traffic against a locally launched server is approved as of the 2026-08-19 scope revision (`docs/PROJECT_SPEC.md` §1.1); real services, accounts, and external targets remain prohibited.
- Never target real services, accounts, devices, production systems, or external targets.
- Never use real secrets, implement offensive exploitation, deploy to production, or add paid APIs.
- Do not add threat scenarios, integrations, dependencies, or scope beyond the approved specification without recording the request under `NEEDS_APPROVAL` in `docs/TASKS.md` and obtaining approval.

## Work controls

- Before starting work, read `docs/PROJECT_SPEC.md`, `docs/DECISIONS.md`, `docs/TASKS.md`, and `docs/STATUS.md`.
- Work only on items listed under `AUTO_READY`, unless the user explicitly approves an item under `NEEDS_APPROVAL`.
- Keep `AUTO_READY`, `NEEDS_APPROVAL`, `BLOCKED`, and `DONE` current.
- Do not silently reinterpret an ambiguous requirement. Record the ambiguity and stop at the relevant approval boundary.
- Prefer Python unless repository inspection produces a documented reason to recommend otherwise.
- Keep the design modular and understandable for one undergraduate developer. Avoid unnecessary distributed systems, Kubernetes, cloud deployment, and production OAuth integrations.
- Do not download models or datasets. Do not start long-running or heavy jobs outside the shared coordinator and an explicitly approved experiment plan.
- Preserve reproducibility: record configuration, scenario identifier, seed where applicable, gateway mode, timestamps, and result artifacts for every experiment.
- Never claim an experiment result until it has been run and recorded. `docs/RESULTS.md` must distinguish planned, partial, and completed results.

## Current phase

Real-protocol implementation phase (2026-08-19). The deterministic core (registry, policy, metadata integrity) is implemented and tested. Current work: a real stdio JSON-RPC transport that wires that core into live `tools/call` traffic, evaluated against a locally launched open-source MCP server.
