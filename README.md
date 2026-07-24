# ContextShield

**Nothing secret leaves. Nothing happens off the record.**

ContextShield is an open-source, self-hosted **egress policy and evidence layer
for AI traffic** — the model APIs your applications call today and, from v0.2,
the tool calls your agents make. It deterministically blocks structured secrets,
minimizes regulated-data exposure per policy, and emits a per-crossing
**evidence ledger**. Sold as risk reduction plus proof — never as "no data was
transferred."

Three qualifiers, kept honest on purpose:

- **"Deterministically" is scoped.** It covers designed identifiers — prefixed
  tokens (`AKIA…`, `sk-…`, `ghp_…`) and checksummed formats with structural
  constraints (IBAN: mod-97 + country + length; PAN: Luhn + IIN + length).
  Unprefixed high-entropy strings and bare digit-runs are *heuristic*,
  confidence-gated, and documented as such — see the measured numbers below.
- **Containment, not detection.** ContextShield never claims to detect prompt
  injection. It bounds the blast radius: policy caps which data classes may flow
  to which destinations, so even a compromised agent cannot move what policy
  forbids — and everything it did is on the record.
- **Evidence coverage is 100% by construction.** Every crossing gets a ledger
  line regardless of detector recall. The ledger stores classes, counts,
  offsets, actions, and a body-level SHA-256 — **never values**.

License: Apache 2.0.

---

## Status — v0.1

Covers the programmatic traffic plane: `/chat/completions`, `/messages`, and
`/responses` for OpenAI- and Anthropic-shaped APIs, plus a corpus scanner
(`contextshield scan`). It does **not** cover employees pasting into consumer
chat UIs — that is endpoint DLP, a different product ([non-goals](#non-goals)).

The gateway forwards bytes unmodified when no action fires (byte-identical
passthrough), fails closed on scan errors by default, and never forwards
unscanned traffic silently. The detection engine is a pure `(text, rules) →
findings` library with linear-time (RE2) regex only.

---

## Quickstart (≤ 5 minutes)

The demo blocks a fake AWS key at the gateway. A request-side block happens
**before** anything is forwarded, so no upstream API key is needed to see it work.

**1. Build and run the gateway** (Docker; ~15 MB Alpine image, no model weights):

```bash
docker build -f deploy/Dockerfile -t contextshield:0.1 .
docker run --rm -p 8080:8080 contextshield:0.1
```

Or run the binary directly:

```bash
go build -o contextshield ./cmd/contextshield
./contextshield serve -config shield.yaml
```

The default policy (`shield.yaml`) blocks the `secret.*` classes and logs
everything else.

**2. Send a request carrying a fake AWS key** to the gateway's `/openai` route:

```bash
curl -sS http://localhost:8080/openai/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"my key is AKIAIOSFODNN7EXAMPLE"}]}'
```

The gateway returns a provider-shaped block error (OpenAI/Anthropic error
envelope, code `contextshield_blocked`, carrying **no** secret value) and the
request is never forwarded upstream.

**3. Read the ledger line** the gateway wrote to stdout — one JSON line per
crossing, recording the class blocked, offsets, action, and a body SHA-256, with
no values.

**4. Point your app at the gateway** — one env var, no code change:

```bash
export OPENAI_BASE_URL=http://localhost:8080/openai
```

Run a week with `defaults.action: log_only` to see what actually flows, then
tighten the policy from the evidence.

**5. Scan data at rest** — the same engine, no traffic in the path:

```bash
./contextshield scan ./path/to/corpus     # exit 0 clean / 1 findings / 2 error
```

---

## Detection accuracy (measured)

Published per-class precision/recall from the eval corpus (`contextshield eval
render`). The corpus holds **254 curated entries** across five rule classes —
valid positive instances plus boundary and adversarial negatives (ms-epoch
timestamps vs PAN, wrong-checksum/wrong-country IBANs, high-entropy non-secrets
like git SHAs and UUIDs, out-of-range SSNs and ZIP+4 confusables). An earlier
pass at 326 entries carried large blocks of near-duplicate positives (the same
equivalence class repeated with different random valid values); those inflated
the corpus size without adding real coverage and — for two classes — diluted
genuine misses into a better-looking percentage. Trimmed to the numbers below.

| Class | Precision | Recall | TP | FP | FN | TN | Confidence¹ |
|---|---|---|---|---|---|---|---|
| `regulated.credit_card` | 100.0% | 100.0% | 43 | 0 | 0 | 29 | 0.97 |
| `regulated.iban` | 100.0% | 100.0% | 22 | 0 | 0 | 22 | 0.95 |
| `secret.aws_access_key` | 100.0% | 100.0% | 10 | 0 | 0 | 16 | 0.91 |
| `secret.generic` | 81.8% | 100.0% | 18 | 4 | 0 | 22 | 0.79 |
| `structural.ssn` | 90.2% | 100.0% | 37 | 4 | 0 | 27 | 0.88 |

¹ Confidence is a Laplace-smoothed measured-precision estimate that informs the
policy `min_confidence` gate. It is deliberately never 1.0 — a finite corpus
measures precision but cannot *prove* determinism. A rule's intrinsic confidence
is set by construction, not by these numbers.

These are eval-corpus numbers against curated cases; real-traffic numbers will
differ. Published honestly, unflattering entries included — `eval run` passes
its CI gate on all five classes:

- **`credit_card` and `iban` hold 100% precision** against every adversarial
  negative — including 13-digit millisecond-epoch timestamps that pass Luhn.
  Their confidence is deterministic by construction (checksum + structural
  constraints), and the corpus does not weaken it.
- **`aws_access_key` holds 100% precision / 100% recall**, including the
  boundary near-misses that previously false-fired: an `AKIA` sequence embedded
  inside a longer token (`MAKIAVELLIAN0POLITICS`, left edge) and an over-length
  run (`AKIA` + 17 chars, right edge). Both were a candidate-window bug — the
  regex saw a slice edge instead of the true neighbor byte, so `\b` matched
  falsely at the window boundary — now fixed by carrying one real byte of
  context on each side of the window (the candidate-window boundary fix). The pattern
  is deterministic by construction (confidence 1.0 intrinsically; 0.91 is the
  Laplace-smoothed measured estimate, which never reaches 1.0 by design).
- **`generic` (entropy heuristic) measures 81.8% precision / 100% recall**,
  clearing its 80% floor. Recall reached 100% by closing two known gaps:
  separator-less `apikey=` (the keyword prefilter now lists `apikey`) and
  JSON-quoted `"api_key":` values (the pattern now tolerates the key's closing
  quote before the separator). It still over-fires on 4 high-entropy
  non-secrets (git SHAs, hex ids, placeholders) — the honest residual of an
  entropy heuristic, which is never confidence 1.0.
- **`structural.ssn` measures 90.2% precision.** With no checksum available
  (SSN area validation ended with 2011 randomization), ZIP+4 codes in the SSA
  area range are genuine confusables. Structural detection is expected to
  produce false positives; it ships confidence-gated at 0.85.

Reproduce: `contextshield eval render` (or `eval run` for the CI gate, which
now passes on all five classes).

---

## Latency (measured)

Added latency the gateway introduces, measured on localhost with all five
production rules loaded. Reproduce with the benchmarks in `gate/`.

| Path | Variant | p50 added | p99 added |
|---|---|---|---|
| Request (non-streaming) | clean passthrough | ~0.07 ms | ~0.25 ms |
| Request (non-streaming) | scan + mask | ~0.07 ms | ~0.26 ms |
| Streaming TTFT | clean | ~1.1 ms | ~2–6 ms |

Streaming TTFT stays far under the ≤ 50 ms p50 target the streaming scanner
commits to (automaton-state hold-back). Reproduce:

```bash
go test -run '^$' -bench 'BenchmarkRequestPathLatency|BenchmarkStreamingTTFT' ./gate/
```

## Test suite quality (mutation testing)

Mutation score per package (bar: ≥90%; <70% would block shipping), measured with
[gremlins](https://github.com/go-gremlins/gremlins):

| Package | Mutants killed | Score |
|---|---|---|
| `engine/` | 174 / 191 covered | **91.1%** |
| `evals/` | 27 / 27 | 100.0% |
| `gate/` | 123 / 138 | **89.1%** |

`engine/` and `evals/` clear the 90% bar. `gate/` measures **89.1% raw** —
technically under the bar. The 15 surviving mutants there include some that are
genuinely equivalent or unreachable without exercising code outside `gate/`
(`adapter/` internals, a `crypto/rand` error path), but not all 15 are proven
equivalent — several are "not tested without going out of scope," which is a
narrower claim. Publishing the raw number rather than an adjusted "100%": that
adjustment has not been independently verified and is not asserted here as fact.

`engine/` remeasured 2026-07-18 after the candidate-window boundary fix
The candidate-window boundary fix produced **91.1% test efficacy** (174 killed / 191 covered,
17 lived), **90.1% mutator coverage** (191 covered / 212 non-timeout total, 21
not covered). 44 additional mutants timed out and are excluded from both
figures — some are genuine (negating an Aho-Corasick loop condition in
`automaton.go` produces a real infinite loop, expected and unkillable by
design), but most timed out only because `gremlins`' default worker count runs
many mutants' recompiles concurrently, and the resulting CPU contention blows
each mutant's timeout; **`--workers 1` is required to get real verdicts instead
of wall-to-wall timeouts** (a run with default workers on this machine returned
almost nothing but `TIMED OUT`). Of the 17 survivors, one is new
(`engine.go:531`, the left-context clamp `windowStart < 0` — an equivalent
mutant: `<=` behaves identically because the clamp is a no-op exactly when
`windowStart == 0`); the other 16 predate this fix. The prior 250/270 (92.6%)
figure was measured before D-26 and is superseded by the number above.

Reproduce: `gremlins unleash --workers 1` against `engine/`, `gate/`, `evals/`
(test files: `engine/mutation_kill_test.go`,
`engine/mutation_stream_kill_test.go`, `gate/mutation_kill_test.go`,
`evals/eval_test.go`). `gate/` and `evals/` were not remeasured this session
(unchanged by the D-26 fix); their numbers above are the Day-7 figures.

---

## Non-goals

These bound what ContextShield is. Version-scoped items live in
[ARCHITECTURE.md](ARCHITECTURE.md); permanent positioning is summarized below.

**v0.1 (sequencing — arrives later):** Agent-plane (MCP/A2A) adapters (v0.2);
NER / LLM-judge tiers (v0.3 / v0.6, ships with published recall); `tokenize` /
vault / restore (gated on a vault threat model, v0.4); `/embeddings` proxying
(v0.6); plugin runtime / WASM; multimodal.

**Permanent (positioning):**

- **Browser / shadow-AI plane.** Employees pasting into consumer chat UIs is
  endpoint DLP — a different product.
- **Platform-gateway and MCP-plumbing features.** Routing, failover, caching,
  dashboards, MCP federation, container isolation — the plumbing tier is a
  compose target, never a competitor.
- **Selling "no data was transferred."** The claim is risk reduction plus proof,
  always.
- **Claiming injection detection.** ContextShield bounds effects; it never scores
  intent.
- **Transparent TLS-terminating MITM as the architecture.** Completeness comes
  from network egress rules, not certificate tricks.

---

## How it works

- **Gateway** — explicit proxy; scans request and response bodies via
  provider-shaped adapters, applies `class × destination → action`
  (`block` / `mask` / `log_only`), emits a ledger line per crossing.
- **Engine** — pure YAML-rule detection: prefixed-token secrets, entropy
  (confidence-gated), Luhn + IIN + length, IBAN mod-97, SSN structural range.
- **Streaming** — SSE responses scanned with automaton-state hold-back so
  bounded patterns add near-zero TTFT.
- **Scanner** — the same engine over files/dirs, with CI-friendly exit codes.

Design detail: [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Contributing

The contribution surface is **data**: detection rules and eval cases as YAML.
Every rule ships with positive **and** negative eval cases, and `eval run` gates
rule changes in CI. Thresholds come from measured corpus FP rates, never
hardcoded guesses.
