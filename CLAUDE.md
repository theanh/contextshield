# ContextShield — Working Agreement

Open-source, self-hosted **egress policy + evidence layer for AI traffic**. Model APIs are in scope now; direct agent/MCP tool calls are planned later. Never position the project as an MCP gateway. Language: Go. Public architecture: [ARCHITECTURE.md](ARCHITECTURE.md).

## Principles

1. Reason from fundamentals.
2. Keep one authoritative source for each fact.
3. Explain why, then how, then what.

## Security guardrails

- Never output or store passwords, API keys, tokens, or credentials.
- Mask secret-shaped strings in reports and logs.
- Never push secrets to remote servers.
- The ledger never stores matched values.
- Preserve byte-identical passthrough when no action fires.
- Never forward unscanned traffic silently.
- Use only linear-time regular expressions.
- Every rule has `max_match_len` plus positive and negative evaluation cases.
- Keep the engine pure: no I/O or network access.
- Confidence `1.0` is only for deterministic-by-construction detection.

## Honesty register

Never claim that no data was transferred. Never claim prompt-injection detection; the product bounds effects through egress policy and records crossings. Publish measured precision/recall and latency, including unflattering results.

## Testing bar

Tests should be explicit and table-driven. Rules must pass `go run ./cmd/contextshield eval run`. Mutation results must be published honestly. Thresholds must come from measured evaluation data, never guesses.

## Current state

Gateway, detection engine, policy evaluator, streaming scanner, filesystem scanner, eval runner, and measured benchmarks are implemented. Open work is tracked in the project issue tracker and must not weaken the architecture invariants.
