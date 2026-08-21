# Status

<!-- historical: 프로젝트 착수 시점 -->
> **이 문서는 기록이다.** 착수 시점의 단계 게이트 상태다 — 무엇을 아직 하지
> 않았고 다음에 무엇이 승인됐는지를 적어둔 것이다.
>
> 그 뒤로 달라진 것: 정책·무결성·감사·전송 계층을 구현하고 실제 MCP 서버 2종을 상대로 돌렸다. 코어 원장을 authority로 결합했다.
>
> 지금 상태는 [README](../README.md)에 있다. 여기 적힌 "아직 하지 않았다"는 문장들은
> **당시의 사실**이고 지금은 맞지 않는다. 조용히 고치면 착수 때 무엇을 의도적으로
> 미뤘는지가 사라지므로, 고치는 대신 선언한다.
>
> 낡았다는 것이 선언이면 기록이고, 선언이 아니면 사고다.

## Current phase

**Approved specification and planning documentation.** The repository scaffold exists and the approved MCP gateway research scope has been documented. Full application implementation and experiment execution have not started.

## Completed

- Repository initialized on `main` with the controlled scaffold.
- Project goal, approved capabilities, threat/failure set, MVP, restrictions, and evaluation measures documented.
- MVP, optional extensions, and out-of-scope work separated explicitly.
- Deterministic policy enforcement recorded as authoritative.
- Approval gates and safe `AUTO_READY` planning tasks defined.
- Reproducible experiment protocol, metrics, audit fields, and acceptance criteria defined.

## Not started

- Repository and environment inspection tasks listed in `AUTO_READY`.
- Architecture or testbed skeletons.
- Dependency selection.
- Application implementation.
- Synthetic scenario execution or full evaluation.

## Safety state

- No datasets or models have been downloaded.
- No real credentials or services are configured.
- No long-running jobs have been started.
- No production deployment, persistent service, or paid API has been added.

## Next authorized work

Start with task A1 in `docs/TASKS.md`: inspect and inventory the repository. This is a bounded read-only inspection plus documentation update; it does not authorize application implementation.
