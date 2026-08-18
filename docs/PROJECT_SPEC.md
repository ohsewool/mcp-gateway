# Project Specification: MCP Security & Reliability Gateway

## 1. Project goal

Build and evaluate an MCP-aware proxy gateway positioned at the host boundary that improves the security, authorization control, reliability, and auditability of MCP tool usage.

The gateway will mediate interactions between an MCP host/client and MCP servers. It will make deterministic, inspectable decisions before tool execution and apply bounded runtime protections around permitted calls.

### 1.1 Scope revision (2026-08-19): real protocol traffic

The original scope limited the testbed to *synthetic* MCP servers described as data structures, with no real protocol messages. That limit is lifted for the following, and only the following:

- The gateway MAY implement the real MCP wire protocol (JSON-RPC 2.0 over stdio) and relay live messages.
- The gateway MAY run **open-source MCP server implementations** (e.g. the reference filesystem server) as local child processes inside this isolated development environment, and exercise them with real traffic.

The safety boundary is unchanged and still binding:

- No real services, accounts, production systems, or external targets. Servers run locally against throwaway directories created by the test suite.
- No real credentials or secrets. No production deployment.
- Deterministic policy enforcement remains the authoritative control; the transport layer never overrides a policy decision.
- Offensive exploitation remains out of scope. The gateway blocks; it does not attack.

Rationale: the approved capabilities (metadata integrity, deny-by-default authorization, duplicate-execution protection) cannot be evaluated for real-world validity against data structures alone. Live protocol traffic is required evidence, and running a local open-source server in an isolated sandbox introduces no real-world target.

## 2. Approved core capabilities

1. Controlled MCP server and tool registration.
2. Tool metadata and schema integrity monitoring.
3. Deterministic authorization and least-privilege policy enforcement.
4. Just-in-time approval for consequential actions.
5. Filesystem, network, command, and resource restrictions.
6. Timeout, retry, circuit-breaker, and idempotency controls.
7. Structured audit traces.
8. A safe synthetic MCP attack and failure testbed.
9. Security and reliability evaluation.

## 3. Approved threat and failure set

The testbed is limited to these synthetic scenarios:

- malicious or changed tool metadata;
- indirect prompt injection through tool output;
- over-privileged tool access;
- confused-deputy behavior;
- destructive or exfiltration-oriented tool requests;
- timeout and retry loops;
- duplicate execution; and
- malformed tool output.

No additional threat or failure scenario is in scope without approval.

## 4. MVP

The minimum viable research artifact consists of:

- one local gateway process;
- a real stdio JSON-RPC transport that relays `initialize`, `tools/list`, and `tools/call` between a client and a locally launched MCP server;
- one or more isolated MCP servers (synthetic fixtures for unit tests, real open-source servers for integration evidence);
- controlled server and tool registration;
- metadata and schema integrity checks;
- an authoritative deterministic policy engine;
- one just-in-time approval flow for a consequential synthetic action;
- bounded timeout and retry handling;
- idempotency or duplicate-execution protection;
- structured audit logging; and
- a bounded test suite covering the approved synthetic attack and failure scenarios.

The MVP architecture should expose understandable modules for the registry, policy engine, approval flow, runtime controls, audit, and synthetic testbed. A single-process modular design is preferred unless repository inspection demonstrates a concrete need for another approach.

## 5. Optional extensions

Optional extensions are not part of the MVP and require approval before work begins. Examples include:

- non-authoritative heuristic or LLM risk signals;
- additional MCP transports, hosts, or server implementations;
- a user interface beyond the minimum approval flow;
- new third-party dependencies;
- performance optimization beyond what is needed to run the evaluation; or
- any broader scenario, integration, or deployment target.

An optional signal may enrich an audit record or request human review, but it may not override, weaken, or replace deterministic policy enforcement.

## 6. Out of scope

- Real services, accounts, devices, production systems, or external targets.
- Real credentials, secrets, personal data, proprietary datasets, or downloaded model artifacts.
- Offensive exploitation or weaponized proof-of-concept behavior.
- Threats or failure modes outside the approved set.
- LLM-based policy enforcement as an authoritative control.
- Production deployment or production OAuth integrations.
- Paid APIs without explicit approval.
- Unnecessary distributed systems, Kubernetes, or cloud deployment.

## 7. Implementation constraints

- Prefer Python unless repository inspection strongly justifies another language.
- Keep the project understandable, runnable, and reproducible by one undergraduate developer.
- Separate registry, policy, approval, runtime-control, audit, and testbed responsibilities through clear module boundaries.
- Use synthetic data and mock credentials only.
- Make policy decisions deterministic for the same normalized request, policy version, registry version, and approval state.
- Bound retries, timeouts, resource use, and test duration.
- Do not begin full implementation until separately authorized.

## 8. Evaluation design

Compare at least these configurations:

1. **Unprotected baseline:** synthetic MCP calls pass through without gateway security or reliability controls, while the test harness still records measurements safely.
2. **Deterministic security controls:** registry, integrity, policy, restriction, approval, and audit controls are active.
3. **Security plus reliability controls:** deterministic security controls plus timeout, bounded retry, circuit-breaker, and duplicate-execution protections are active.

Measure:

- attack blocking rate;
- false-positive rate;
- policy-decision consistency;
- metadata-change detection;
- duplicate-execution prevention;
- timeout and failure recovery;
- task success rate;
- latency overhead; and
- audit completeness.

The detailed reproducible protocol and metric definitions are in `docs/EXPERIMENT_PLAN.md`.

## 9. MVP acceptance criteria

The MVP is accepted only when all of the following are demonstrated in the isolated synthetic testbed:

- Every server and tool used in a protected configuration is registered; unregistered identities are denied.
- Every injected metadata or schema mutation in the approved test corpus is detected before execution.
- Repeated identical policy inputs produce identical decisions in 100% of consistency trials.
- Every explicitly forbidden synthetic action in the approved corpus is blocked before side effects.
- The benign-scenario false-positive rate is no greater than 5%.
- The approval-required scenario cannot execute without a matching, current approval and cannot reuse an expired or mismatched approval.
- Retry counts and timeout durations never exceed configured bounds.
- Every injected duplicate carrying the same idempotency identity produces at most one synthetic side effect.
- Every malformed tool result is identified and handled without an uncontrolled gateway failure.
- Protected benign task success is no more than five percentage points below the unprotected baseline.
- Latency overhead is reported using at least median and 95th-percentile values for each configuration; no performance claim is made without those measurements.
- Every protected trial produces a complete structured audit trace with the required fields defined in `docs/EXPERIMENT_PLAN.md`.
- A clean checkout can reproduce the test corpus and evaluation using documented local commands without real secrets, datasets, models, external targets, or paid APIs.

## 10. Deliverables

- Local gateway MVP.
- Isolated synthetic MCP server/testbed fixtures.
- Versioned deterministic policy and registry fixtures.
- Reproducible evaluation harness and configuration.
- Structured audit traces containing synthetic data only.
- Experiment results and limitations documented in `docs/RESULTS.md`.

This document defines scope, not authorization to begin full implementation.
