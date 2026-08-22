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

> **착수 단계 게이트는 소진됐다 (2026-08-21).** 위의 "Work only on items listed under AUTO_READY"는 착수 시점의 제약이고,
> 그때는 맞았다. 지금 이 저장소에는 정책·무결성·감사·전송 계층이 구현돼 있고 실제 MCP 서버 2종을 상대로 돌며 테스트 321개가 돈다. 그 문장을 그대로 두면 **다음 작업이 이미
> 끝난 단계로 되돌아간다** — 형제 저장소 `rag-profile-selector`의 `AGENTS.md`가 몇 달간
> 쓰지 않는 코퍼스를 지시하고 있던 것과 같은 종류의 사고다.
>
> `docs/TASKS.md`와 `docs/STATUS.md`는 착수 계획의 **기록으로 선언**돼 있다. 지금 상태를
> 알려면 [README](README.md)와 그 문서들이 가리키는 실제 결과를 본다.
>
> **아래 안전 제약은 그대로 유효하다** — 실서비스·실계정·실크리덴셜 금지, 승인 없는
> 다운로드·장시간 작업 금지, 측정하지 않은 결과를 주장하지 않기. 소진된 것은 단계
> 게이트뿐이다.

- Keep `AUTO_READY`, `NEEDS_APPROVAL`, `BLOCKED`, and `DONE` current.
- Do not silently reinterpret an ambiguous requirement. Record the ambiguity and stop at the relevant approval boundary.
- Prefer Python unless repository inspection produces a documented reason to recommend otherwise.
- Keep the design modular and understandable for one undergraduate developer. Avoid unnecessary distributed systems, Kubernetes, cloud deployment, and production OAuth integrations.
- Do not download models or datasets. Do not start long-running or heavy jobs outside the shared coordinator and an explicitly approved experiment plan.
- Preserve reproducibility: record configuration, scenario identifier, seed where applicable, gateway mode, timestamps, and result artifacts for every experiment.
- Never claim an experiment result until it has been run and recorded. `docs/RESULTS.md` must distinguish planned, partial, and completed results.

## Current phase

Real-protocol implementation phase (2026-08-19). The deterministic core (registry, policy, metadata integrity) is implemented and tested. Current work: a real stdio JSON-RPC transport that wires that core into live `tools/call` traffic, evaluated against a locally launched open-source MCP server.
