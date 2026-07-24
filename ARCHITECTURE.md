# ContextShield Architecture

ContextShield is a self-hosted egress policy and evidence layer for programmatic AI traffic. It has two operational planes:

- `serve`: scans model API requests and responses before they cross the network boundary.
- `scan`: scans files, directories, repositories, and corpora before ingestion.

Both planes use the same pure detection engine, rules, findings schema, and policy model.

## System boundaries

Application services send model API traffic to the gateway. The gateway selects an upstream, scans the request, applies policy, forwards permitted bytes, scans the response, and emits one ledger record per direction. Network policy is responsible for ensuring that applications cannot bypass the explicit gateway.

The v0.1 API boundary covers OpenAI chat completions, OpenAI responses, and Anthropic messages. Tool definitions, tool arguments, and tool results are scanned when they travel inside those model API payloads. Direct MCP/A2A tool-execution traffic is outside v0.1.

## Invariants

1. The ledger never stores matched values. It stores classes, counts, offsets where available, actions, and a body-level SHA-256.
2. If no action fires, the original request or response bytes are forwarded unchanged.
3. Unscanned traffic is never forwarded silently. Unknown fields are visible in the ledger; strict deployments may reject them.
4. Rules use Go's RE2-class regular expressions and bounded candidate windows.
5. Every rule declares `max_match_len` and has positive and negative evaluation cases.
6. The detection engine has no file, network, or other I/O.
7. Confidence `1.0` is reserved for deterministic-by-construction detection. Heuristic matches are confidence-gated.
8. Semantic detection tiers must run locally inside the trust boundary.
9. The v0.1 gateway is stateless and has no value vault.
10. Errors and logs never claim that no data was transferred.

## Components

```text
cmd/contextshield  CLI: serve, scan, eval
gate/              HTTP gateway, routing, request/response actions, SSE scanner
adapter/           Provider-shaped JSON extraction and byte-range mapping
engine/            Pure rules-as-data matcher, validators, offsets, streaming state
policy/            shield.yaml loading and class × destination evaluation
ledger/            Synchronized NDJSON evidence writer
scan/              Filesystem scanner using the engine and findings schema
evals/             Corpus loader, evaluator, thresholds, and report renderer
rules/             YAML detection rules
deploy/            Container image and Kubernetes egress recipe
```

## Request flow

1. Read the complete request body and compute its body hash.
2. Resolve the upstream from the route prefix or model name.
3. Parse the provider payload without reserializing it.
4. Extract known text-bearing fields, including tool definitions, arguments, and results.
5. Run the pure engine on each extracted unit and map decoded offsets back to raw bytes.
6. Evaluate every finding against class, destination, confidence, and exemptions.
7. Block, mask, log, or forward according to the resulting actions.
8. Emit the request ledger line before forwarding.
9. Forward the original bytes unless masking changed them.

## Response flow

Non-streaming responses are read, scanned, optionally masked or blocked, recorded, and returned.

SSE responses are parsed into provider-specific text deltas. `engine.StreamScan` maintains automaton state across chunks and holds only bytes that could still become part of a match. Safe bytes are flushed immediately. A response block stops forwarding and emits a terminal provider-shaped SSE error without including the matched value.

## Detection engine

Rules are YAML data with an identifier, class, pattern, confidence, `max_match_len`, optional prefilter, validators, and examples. Aho-Corasick anchors find bounded candidate windows; RE2 confirmation and validators run only inside those windows.

The current v0.1 rules cover:

- prefixed AWS-style access keys;
- generic high-entropy key/value secrets;
- credit-card PANs with Luhn, issuer-prefix, and length validation;
- IBANs with country, length, and mod-97 validation;
- structural US SSNs with allocation-range exclusions.

## Policy

The v0.1 policy formula is:

```text
class × network-observed destination → action
```

Actions are `block`, `mask`, and `log_only`. An optional `min_confidence` threshold falls back to the default action and never converts a low-confidence finding into an automatic block. Exemptions match one exact class and one exact network-observed destination and remain visible in the ledger.

## Ledger

The gateway emits versioned NDJSON records containing timestamp, request ID, direction, destination, model, findings, optional unscanned fields, verdict, body hash, and schema version. Values are never written. Error crossings also receive ledger records.

## Deployment

The container listens on port 8080 and loads `shield.yaml` plus `rules/`. Applications opt in by setting the provider base URL to the gateway. Kubernetes egress policy should permit restricted workloads to reach only the gateway and DNS.

The system is stateless: replicas share no value store or coordination state. Ledger retention, signing, SIEM exports, vault-backed tokenization, semantic detection, routing, and direct agent-plane adapters are later capabilities.

## Evaluation and release evidence

`contextshield eval run` is the rules regression gate. `contextshield eval render` produces the measured per-class precision/recall report. Benchmarks cover request-path latency and streaming TTFT. Mutation testing is a separate quality gate and must meet the project's published threshold before being represented as complete.
