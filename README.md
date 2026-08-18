# MCP Security & Reliability Gateway

에이전트와 MCP 서버 **사이에 실제로 끼어드는** 프록시. 도구 호출이 서버에 닿기 전에 정책으로 판단하고, 위험한 호출은 사람 승인을 요구하며, 모든 결정을 실행 원장에 남긴다.

```
[클라이언트/에이전트] ──stdio JSON-RPC──> [게이트웨이] ──stdio JSON-RPC──> [MCP 서버]
                                             │
                                             ├─ 정책: 이 호출을 허용하는가
                                             ├─ 무결성: 서버가 도구 설명을 바꿨는가
                                             ├─ 승인: 사람이 이 호출을 정확히 승인했는가
                                             └─ 원장: 무엇이 언제 왜 실행됐는가
```

```bash
python3 -m pytest tests/ -q                      # 64 tests
python3 -m pytest tests/ -q -m "not integration" # 실서버 없이
```

## 무엇을 막는가

**정책 차단** — deny-by-default. 등록되지 않은 도구, 명시적으로 거부된 도구, 형식이 깨진 요청은 서버에 도달하지 않는다. 통합 테스트가 증명하는 것은 에러 응답이 아니라 **파일이 생기지 않았다는 사실**이다.

**rug-pull 탐지** — 서버가 등록 이후 도구의 설명이나 입력 스키마를 조용히 바꾸면 `tools/list` 응답을 차단한다. 도구 설명은 모델이 읽는 지시문이므로, 그것이 바뀌었다는 것은 도구가 바뀐 것과 같다.

**JIT 승인** — 결과가 되돌릴 수 없는 도구는 보류된다. 게이트웨이가 요청 범위의 digest를 계산해 실행 의도를 원장에 기록하고, 사람이 승인하면 1회용 lease가 발급된다. 재시도 시 digest를 다시 계산해 **일치할 때만** 통과한다. 인자를 바꿔치기하면 승인이 무효가 되고, 소비된 lease는 두 번째 실행을 만들지 못한다.

**정직한 타임아웃** — 응답이 없으면 실패로 기록하지 않는다. 요청은 이미 전달됐으므로 부작용이 일어났을 수 있다. `UNKNOWN`으로 분류하고 클라이언트에 reconciliation이 필요하다고 알린다. 재시도를 유도하지 않는 것이 핵심이다.

**중복 키 거부** — `{"path": "safe", "path": "../secret"}`을 파서 두 개가 다르게 읽으면 승인한 것과 실행한 것이 달라진다. 파싱 단계에서 거부한다.

## 증거

`tests/test_live_server.py`는 공식 `@modelcontextprotocol/server-filesystem`을 자식 프로세스로 띄우고 실제 JSON-RPC로 대화한다.

| 테스트 | 증명하는 것 |
|---|---|
| `test_denied_call_never_reaches_the_real_server` | 차단된 write 이후 대상 파일이 존재하지 않음 |
| `test_metadata_drift_from_real_server_is_detected` | 등록 기준선과 다른 도구 목록은 차단됨 |
| `test_consequential_write_requires_approval_then_happens_exactly_once` | 승인 전 파일 없음 → 승인 후 1회 생성 → lease 재사용 시 재기록 없음 |

## 코어와의 관계

승인·lease·결과 기록은 이 저장소가 직접 구현하지 않고 [`agent-safety-core`](../agent-safety-core)의 실행 원장에 위임한다. 게이트웨이는 `ExecutionAuthority` 포트만 알며, 원자적 lease 소비가 외부 호출보다 **먼저** durable commit된다는 보장이 "동일 lease는 최대 1회 dispatch"를 성립시킨다. 코어가 없으면 정책·무결성 계층만으로도 동작한다(승인 테스트는 skip).

## 안전 경계

로컬 격리 환경에서 오픈소스 MCP 서버를 실행하는 것까지가 승인 범위다(`docs/PROJECT_SPEC.md` §1.1). 실서비스·실계정·실크리덴셜·프로덕션 배포는 범위 밖이며, 게이트웨이는 차단할 뿐 공격하지 않는다. 통합 테스트의 서버는 pytest 임시 디렉터리에 갇힌다.

## 남은 작업

- 감사 기록의 영속 저장 형식 결정 (현재는 인터셉터 메모리 + 코어 원장)
- rate limit, 서버별 세션 격리
- HTTP 전송 지원 (현재 stdio만)
