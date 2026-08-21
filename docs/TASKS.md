# Tasks

<!-- historical: 프로젝트 착수 시점 -->
> **이 문서는 기록이다.** 착수 시점의 단계별 작업 목록이다. A1은 "코드·데이터셋·자격증명이 없음을 확인하라"이고, 여러 항목이 "동작을 구현하지 말 것"을 명시한다.
>
> 그 뒤로 달라진 것: 정책·무결성·감사·전송 계층을 구현하고 실제 MCP 서버 2종을 상대로 돌렸으며 테스트 239개가 돈다. 범위 해제는 [`PROJECT_SPEC.md`](PROJECT_SPEC.md)가 이미 기록해 두었다.
>
> 지금 상태는 [README](../README.md)에 있다. 여기 적힌 "아직 하지 않았다"·"구현하지 말라"는
> 항목들은 **당시의 사실이자 당시의 제약**이다. 체크박스를 지금 채우면 계획을 그대로
> 따른 것처럼 보이고, 실제로 어디서 갈라졌는지가 사라진다. 그래서 고치지 않고 선언한다.
>
> 낡았다는 것이 선언이면 기록이고, 선언이 아니면 사고다.

Only tasks in `AUTO_READY` may proceed without further scope approval. Completing a planning or skeleton task does not authorize full application implementation.

## AUTO_READY

### Repository inspection

- [ ] **A1 — Inspect and inventory the repository.** Confirm branch and working-tree state; inventory documentation and configuration; verify that no application code, datasets, models, credentials, generated artifacts, or unexpected dependencies are present. Record findings in `docs/STATUS.md` without modifying external locations.
- [ ] **A2 — Validate repository controls.** Review `.gitignore`, repository instructions, and documentation links against the approved safety and reproducibility boundaries; propose corrections only within the approved scope.

### Environment bootstrap

- [ ] **A3 — Specify the minimal local development environment.** Document the selected Python version, isolated environment procedure, local-only configuration, and verification commands. Do not add a dependency without moving that decision to `NEEDS_APPROVAL`.
- [ ] **A4 — Define deterministic configuration conventions.** Specify local paths, mock-credential naming, seed handling, timeout units, policy/registry version identifiers, and safe defaults without creating real credentials or downloading artifacts.

### Architecture skeleton

- [ ] **A5 — Draft the component interfaces.** Define responsibilities and data contracts for registry, policy engine, approval, runtime controls, audit, gateway orchestration, and synthetic testbed. Include request normalization, decision reasons, error types, and module dependency direction; do not implement behavior.
- [ ] **A6 — Draft the project layout.** Propose a minimal single-process Python package and test layout that maps directly to the approved modules and keeps adapters separate from authoritative policy logic; do not add application implementation.
- [ ] **A7 — Define policy and registry schemas.** Document the deterministic inputs, outputs, canonicalization rules, integrity identifiers, least-privilege resource bounds, and deny-by-default behavior using synthetic examples only.
- [ ] **A8 — Define approval and runtime-control state machines.** Document approval binding/expiry, timeout, bounded retry, circuit-breaker, and idempotency transitions, including how every transition is audited; do not implement the state machines.
- [ ] **A9 — Define the audit event schema.** Document required fields, event ordering, correlation and idempotency identifiers, redaction rules, and completeness validation using synthetic records only.

### Testbed skeleton

- [ ] **A10 — Specify synthetic MCP fixtures.** Define minimal benign tools and isolated synthetic side effects needed to exercise the approved threat and failure set. Keep all endpoints local and all credentials fake; do not implement offensive exploitation.
- [ ] **A11 — Map the bounded scenario corpus.** Map each approved threat/failure to preconditions, synthetic input, expected gateway decision, expected side effect, audit assertions, and safe teardown. Do not add scenarios outside the approved set.
- [ ] **A12 — Define test isolation controls.** Specify temporary-directory boundaries, loopback-only networking, subprocess limits, command allowlists, cleanup expectations, and proof that fixtures cannot reach real targets.

### Test planning

- [ ] **A13 — Freeze metric definitions and run matrix.** Review `docs/EXPERIMENT_PLAN.md`, assign stable scenario identifiers, and prepare a versioned matrix covering all three configurations and all approved scenarios.
- [ ] **A14 — Prepare acceptance checks.** Translate the approved acceptance criteria into testable assertions for security, reliability, task success, latency reporting, audit completeness, and reproducibility; do not execute long-running jobs.
- [ ] **A15 — Prepare a short smoke-test protocol.** Define a bounded local dry run that validates isolation, configuration, and result capture before the full experiment is separately authorized.

## NEEDS_APPROVAL

- [ ] Begin application implementation beyond documentation, interface definitions, and empty architecture/testbed skeletons.
- [ ] Add any new runtime or development dependency, including MCP SDK, schema, testing, policy, logging, or retry libraries.
- [ ] Add any capability or scope beyond `docs/PROJECT_SPEC.md`.
- [ ] Add any threat or failure scenario beyond the approved set.
- [ ] Integrate a real service, account, device, production system, cloud resource, external target, or non-synthetic credential.
- [ ] Use any paid API or service.
- [ ] Add any heuristic or LLM risk signal, even as a non-authoritative secondary signal.
- [ ] Change deterministic policy enforcement from the authoritative control.
- [ ] Add production deployment, production OAuth, a distributed system, Kubernetes, or a persistent service.
- [ ] Start the full experiment run or any long-running/heavy job.
- [ ] Change frozen acceptance thresholds or the experiment corpus after evaluation begins.

## BLOCKED

- None. Implementation and full experiment execution remain intentionally unstarted pending approval, but current planning tasks are not blocked.

## DONE

- [x] Initialize the controlled research repository on `main`.
- [x] Approve the MCP Security & Reliability Gateway scope, constraints, MVP, threat/failure set, and evaluation measures.
- [x] Replace placeholder documentation with the approved project specification and planning controls.
