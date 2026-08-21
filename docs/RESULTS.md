# Results

## Result status

**No experiments have been run. No security, reliability, performance, or task-success claims are available.**

This file defines the reporting structure only. Planned acceptance criteria are not results.

## Experiment record template

### Identification

- Experiment version:
- Commit hash:
- Date/time and timezone:
- Operator:
- Gateway/testbed version:
- Corpus and run-manifest version:
- Registry, policy, configuration, and audit-schema versions:
- Python and dependency-lock versions:
- Configuration: B0 / S1 / SR2

### Safety and reproducibility checks

- Synthetic-only fixtures confirmed:
- Mock credentials confirmed:
- Loopback/temporary-directory isolation confirmed:
- External targets absent:
- Resource and duration bounds confirmed:
- Smoke test result:
- Protocol deviations:

### Measurements

Report numerator, denominator, rate, sample count, and uncertainty where applicable:

- Attack blocking rate:
- False-positive rate:
- Policy-decision consistency:
- Metadata-change detection:
- Duplicate-execution prevention:
- Timeout-bound compliance:
- Retry-bound compliance:
- Circuit-breaker and next-request recovery:
- Task success rate:
- Median latency overhead:
- 95th-percentile latency overhead:
- Audit completeness:

### Acceptance assessment

- Unregistered calls denied:
- Metadata-change detection = 100%:
- Policy consistency = 100%:
- Forbidden-action blocking = 100%:
- False-positive rate <= 5%:
- Approval binding/expiry checks all pass:
- Timeout/retry bound violations = 0:
- Duplicate prevention = 100%:
- Uncontrolled malformed-output failures = 0:
- Protected benign success within five percentage points of B0:
- Latency median/p95 and sample counts reported:
- Audit completeness = 100%:
- Overall MVP result: PASS / FAIL / INCOMPLETE

### Failures, limitations, and interpretation

- Failed scenarios:
- Unexpected behavior:
- Missing or invalid data:
- Generalizability limits:
- Follow-up requiring approval:

## Current findings

**이 문장은 더 이상 사실이 아니었다.** 원래 "None. The project remains in the specification and planning phase."였고, 착수 시점에는 맞았으며 그 뒤로 고쳐지지 않았다.

이 파일에는 없다. 실제 측정은 [README](../README.md)에 있다 — 정책·무결성·감사·전송 계층과 실제 MCP 서버 2종을 상대로 한 결과, 그리고 코어 원장 결합.

아래 템플릿은 그대로 둔다 — 보고 구조를 정의하는 것이 이 파일의 나머지 역할이다.
