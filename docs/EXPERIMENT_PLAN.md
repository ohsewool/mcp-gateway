# Experiment Plan

## 1. Purpose

Evaluate whether the MCP Security & Reliability Gateway improves security, authorization control, reliability, and auditability without unacceptable loss of benign task success. Experiments are local, isolated, synthetic, bounded, and reproducible.

No experiment is authorized to contact real services, use real credentials, download datasets/models, or exercise a threat outside the approved set.

## 2. Compared configurations

Use the same gateway/testbed version, scenario corpus, inputs, and run order manifest for all configurations:

1. **B0 — Unprotected baseline:** pass synthetic calls through without gateway security or reliability enforcement. The harness still enforces outer isolation and records measurements.
2. **S1 — Deterministic security controls:** enable controlled registration, integrity monitoring, deterministic policy, least privilege, restrictions, just-in-time approval, and structured audit.
3. **SR2 — Security plus reliability controls:** enable S1 plus timeouts, bounded retries, circuit breaker, and idempotency/duplicate protection.

The baseline is unprotected only with respect to the evaluated gateway controls; testbed isolation remains mandatory in every configuration.

## 3. Scenario corpus

Assign immutable identifiers to benign controls and to cases covering only:

- malicious or changed tool metadata;
- indirect prompt injection through tool output;
- over-privileged tool access;
- confused-deputy behavior;
- destructive or exfiltration-oriented tool requests;
- timeout and retry loops;
- duplicate execution; and
- malformed tool output.

Each scenario definition must include: identifier, corpus version, category, benign/adversarial label, fixture version, preconditions, normalized request, expected policy decision by configuration, expected synthetic side effect, expected runtime behavior, expected audit events, timeout budget, maximum attempts, and cleanup rule.

## 4. Reproducible protocol

### 4.1 Freeze inputs

Before an evaluated run, commit or checksum the scenario corpus, registry, policy, gateway/testbed revision, configuration files, audit schema, and run manifest. Record the local Python version and dependency lock state. Any post-freeze change creates a new experiment version.

### 4.2 Verify isolation

Before every run:

- confirm all fixtures use temporary directories and loopback-only endpoints;
- confirm all credentials are visibly marked mock values;
- confirm no real service or external target is configured;
- confirm command, filesystem, network, process, duration, and resource bounds;
- confirm the coordinator reports no other heavy job if the run is classified as heavy; and
- run the separately defined short smoke test before a full run.

### 4.3 Trial matrix

Run every scenario under B0, S1, and SR2. Use at least 20 trials per configuration/scenario pair for nondeterministic timing measures and all applicable deterministic input variants for policy assertions. Record a fixed run-order manifest; alternate or deterministically shuffle configuration order with a recorded seed to reduce ordering bias.

For deterministic consistency, replay each unique normalized policy input at least 20 times using the same policy version, registry version, and approval state. No network access or LLM sampling is part of authoritative policy decisions.

### 4.4 Trial procedure

For each trial:

1. Reset the isolated fixture and synthetic side-effect counter.
2. Load the frozen registry, policy, configuration, and scenario.
3. Record configuration, scenario ID, trial number, seed, versions, and monotonic start time.
4. Submit the synthetic request through the selected configuration.
5. Record policy, approval, runtime-control, tool-result validation, and audit outcomes.
6. Record synthetic side effects, attempt count, completion state, error class, and monotonic end time.
7. Validate cleanup and isolation before the next trial.

Stop the run if an isolation invariant fails, a real credential/target is detected, configured resource bounds are exceeded, or audit output contains a suspected secret.

## 5. Metric definitions

- **Attack blocking rate:** adversarial trials blocked before a prohibited synthetic side effect divided by all adversarial trials expected to be blocked.
- **False-positive rate:** benign trials incorrectly denied or made to fail by gateway controls divided by all benign trials expected to succeed.
- **Policy-decision consistency:** replay groups in which every decision and reason code matches the first decision divided by all deterministic replay groups.
- **Metadata-change detection:** injected metadata/schema mutations detected before execution divided by all injected mutations.
- **Duplicate-execution prevention:** duplicate-injection trials producing no more than one synthetic side effect divided by all duplicate-injection trials.
- **Timeout and failure recovery:** report timeout-bound compliance, retry-bound compliance, circuit transitions, terminal state, and recovery of the next eligible benign request.
- **Task success rate:** benign trials reaching the expected synthetic outcome divided by all benign trials.
- **Latency overhead:** protected latency minus matched B0 latency; report median, 95th percentile, and distribution/sample count by configuration and scenario.
- **Audit completeness:** protected trials whose trace contains every required field and event for that path divided by all protected trials.

Report numerators, denominators, counts, and uncertainty where applicable; do not report only percentages.

## 6. Required audit fields

At minimum, each protected trial must provide sufficient correlated events to reconstruct:

- trace ID, request ID, scenario ID, trial number, and idempotency identity;
- timestamp and monotonic duration;
- gateway, testbed, corpus, configuration, registry, policy, and audit-schema versions;
- synthetic server and tool identity plus metadata/schema integrity result;
- normalized action and bounded resource attributes without secret values;
- deterministic decision, reason code, matched rule, and approval state/identity if applicable;
- attempt number, timeout, retry, circuit-breaker, and duplicate-handling events;
- tool-result validation and terminal outcome; and
- synthetic side-effect identity/count and error class.

## 7. Acceptance criteria

The experiment is valid only if the frozen artifacts, isolation checks, complete run manifest, raw structured traces, metric derivation, and environment record are retained using synthetic data only.

The MVP passes when:

- unregistered protected calls are denied;
- metadata-change detection is 100% for the frozen mutation corpus;
- policy-decision consistency is 100%;
- attack blocking is 100% for explicitly forbidden actions in the frozen corpus;
- false-positive rate is at most 5%;
- approval binding, matching, and expiry checks pass for every approval trial;
- timeout and retry bounds are exceeded in 0 trials;
- duplicate-execution prevention is 100% for injected duplicates;
- malformed output causes 0 uncontrolled gateway failures;
- protected benign task success is no more than five percentage points below B0;
- median and 95th-percentile latency overhead are reported with sample counts for S1 and SR2; and
- audit completeness is 100% for protected trials.

A criterion that cannot be measured is a failed evaluation gate, not a passing result. Threshold changes after the corpus is frozen require approval and a new experiment version.

## 8. Result reporting

Write results to `docs/RESULTS.md` only after execution. Include artifact revisions, environment, protocol deviations, raw counts, computed metrics, acceptance decision, limitations, and failures. Clearly label exploratory or partial runs and never combine them with the frozen confirmatory evaluation.
