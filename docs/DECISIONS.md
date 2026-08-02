# Decisions

## Approved decisions

### D-001: Host-boundary gateway

Place one local MCP-aware proxy gateway between the host/client and isolated synthetic MCP servers. This boundary centralizes registration, authorization, runtime controls, and audit generation.

### D-002: Deterministic policy is authoritative

Authorization uses explicit deterministic policy over normalized request context, registered metadata, resource constraints, and approval state. Any future heuristic or LLM risk signal is secondary and cannot grant access, override a denial, or weaken a restriction.

### D-003: Controlled registration and integrity baseline

Protected configurations use an allowlisted registry of synthetic servers and tools. Canonicalized tool metadata and schemas are integrity-checked against a versioned baseline before execution.

### D-004: Least privilege and deny-by-default

Unregistered servers, unknown tools, undeclared resources, and requests outside explicit filesystem, network, command, or resource bounds are denied. Consequential synthetic actions require a just-in-time approval bound to the request and validity window.

### D-005: Bounded reliability controls

Timeouts, retries, circuit breaking, and idempotency are explicit and bounded. Retries must not bypass policy or approval checks, and retryable operations must preserve the same idempotency identity.

### D-006: Structured audit contract

Protected calls emit structured traces covering request identity, configuration, registry and policy versions, decision and reason, approval state, runtime-control events, outcome, timing, and synthetic side-effect identity. Audit records must not contain secrets.

### D-007: Synthetic-only safety boundary

All testing uses local isolated synthetic MCP servers, synthetic data, and mock credentials. No real service, account, device, production system, external target, offensive exploitation, or production deployment is permitted.

### D-008: MVP architecture

Prefer a single local Python process with clear modules for registry, policy, approval, runtime controls, audit, and the synthetic testbed. Favor standard-library capabilities and a small dependency surface; dependency additions require approval.

### D-009: Three-configuration evaluation

Evaluate an unprotected baseline, deterministic security controls, and security plus reliability controls using the same versioned scenario corpus and measurement definitions.

## Decisions requiring approval

The following are intentionally undecided and must not be implemented without explicit approval:

- Any scope expansion or additional threat/failure scenario.
- Any new runtime or development dependency not already approved.
- Any real-service, real-account, device, production, cloud, or external integration.
- Any paid API.
- Any authoritative use of an LLM or heuristic for policy enforcement; this conflicts with the approved scope and would require a scope revision.
- Any optional non-authoritative heuristic or LLM risk signal.
- Any production deployment, OAuth integration, distributed architecture, Kubernetes use, or persistent background service.
- Any change to the quantitative acceptance criteria after evaluation begins.

## Decision procedure

Record a proposed change under `NEEDS_APPROVAL` in `docs/TASKS.md` with its rationale, safety impact, reproducibility impact, dependency/cost impact, and effect on the evaluation. Approval must be explicit before the item moves to `AUTO_READY`.
