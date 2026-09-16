# Agent Instructions

For benchmark setup, scanner execution, review, or publication, follow [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md) and [`METHODOLOGY.md`](METHODOLOGY.md).

- Use one coordinator and delegate the bounded roles described in the execution plan to subagents.
- The coordinator is the only agent that merges, pushes, tags, or publishes.
- Writing subagents use isolated worktrees; read-only reviewers may run in parallel.
- Run scanner processes serially unless the execution plan is deliberately revised before the release is frozen.
- Do not start the three-run baseline until every Phase 0 harness gate is closed and verified in CI.
- Never expose credentials, change the oracle after seeing results, suppress unfavorable findings, union repetitions, or count a failed/unexercised case as clean.
- Preserve unrelated work and failed-attempt evidence.
