package gate

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/theanh/contextshield/engine"
	"github.com/theanh/contextshield/ledger"
	"github.com/theanh/contextshield/policy"
)

// This file hardens the gate package's pure SSE/mask/route helpers and the
// directly-callable scanner methods against surviving gremlins mutants that the
// integration tests leave loose. White-box (package gate), data-provider style.

// --- SSE delta extraction ---------------------------------------------------

func TestExtractStreamDeltaTable(t *testing.T) {
	cases := []struct {
		name          string
		path          string
		eventType     string
		data          string
		wantText      string
		wantUnscanned string
	}{
		{
			name:     "openai chat content delta",
			path:     "/v1/chat/completions",
			data:     `{"choices":[{"delta":{"content":"hello"}}]}`,
			wantText: "hello",
		},
		{
			name:     "openai chat unknown field flagged",
			path:     "/v1/chat/completions",
			data:     `{"choices":[{"delta":{"content":"x"}}],"mystery":1}`,
			wantText: "x", wantUnscanned: "$.mystery",
		},
		{
			name: "anthropic text_delta yields text",
			path: "/v1/messages", eventType: "content_block_delta",
			data:     `{"delta":{"type":"text_delta","text":"secret"}}`,
			wantText: "secret",
		},
		{
			name: "anthropic non-text delta yields nothing",
			path: "/v1/messages", eventType: "content_block_delta",
			data:     `{"delta":{"type":"input_json_delta","partial_json":"{"}}`,
			wantText: "",
		},
		{
			name: "anthropic non-delta event flags unknown fields",
			path: "/v1/messages", eventType: "message_start",
			data:          `{"type":"message_start","weird":1}`,
			wantText:      "",
			wantUnscanned: "$.weird",
		},
		{
			name: "openai responses text delta",
			path: "/v1/responses", eventType: "response.output_text.delta",
			data:     `{"delta":"world"}`,
			wantText: "world",
		},
		{
			name: "openai responses non-delta event flags unknown fields",
			path: "/v1/responses", eventType: "response.completed",
			data:          `{"type":"response.completed","zzz":1}`,
			wantText:      "",
			wantUnscanned: "$.zzz",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractStreamDelta(tc.path, tc.eventType, []byte(tc.data))
			if got.text != tc.wantText {
				t.Fatalf("text = %q, want %q", got.text, tc.wantText)
			}
			if joined := strings.Join(got.unscanned, ","); joined != tc.wantUnscanned {
				t.Fatalf("unscanned = %q, want %q", joined, tc.wantUnscanned)
			}
		})
	}
}

// --- mask offset math -------------------------------------------------------

func TestMaskStringOffsetsTable(t *testing.T) {
	cases := []struct {
		name        string
		content     string
		local       []engine.Finding
		baseOffset  int
		wantMasked  string
		wantOverlap bool
	}{
		{
			name: "interior span masked exactly", content: "0123456789",
			local: []engine.Finding{{Start: 2, End: 5}}, baseOffset: 0,
			wantMasked: "01***56789", wantOverlap: true,
		},
		{
			name: "base offset shifts span into range", content: "BBBB",
			local: []engine.Finding{{Start: 4, End: 8}}, baseOffset: 4,
			wantMasked: "****", wantOverlap: true,
		},
		{
			name: "negative start clamps to zero", content: "abcdef",
			local: []engine.Finding{{Start: -2, End: 3}}, baseOffset: 0,
			wantMasked: "***def", wantOverlap: true,
		},
		{
			name: "end beyond length clamps", content: "abcdef",
			local: []engine.Finding{{Start: 4, End: 99}}, baseOffset: 0,
			wantMasked: "abcd**", wantOverlap: true,
		},
		{
			name: "zero-width span is no overlap", content: "abcdef",
			local: []engine.Finding{{Start: 3, End: 3}}, baseOffset: 0,
			wantMasked: "abcdef", wantOverlap: false,
		},
		{
			// baseOffset=3 on a 10-byte content: correct end = 5-3 = 2 (short
			// span, not clamped). If `s.End - baseOffset` inverts to `+`, end
			// becomes 5+3=8 — NOT clamped away (content is long enough to hold
			// it) — so a sign bug here is directly observable, unlike the
			// same-length cases above where clamping hides the difference.
			name: "nonzero base offset subtracts, not adds", content: "0123456789",
			local: []engine.Finding{{Start: 2, End: 5}}, baseOffset: 3,
			wantMasked: "**23456789", wantOverlap: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			masked, _, overlap := maskStringOffsets(tc.content, tc.local, tc.baseOffset)
			if masked != tc.wantMasked {
				t.Fatalf("masked = %q, want %q", masked, tc.wantMasked)
			}
			if overlap != tc.wantOverlap {
				t.Fatalf("overlap = %v, want %v", overlap, tc.wantOverlap)
			}
		})
	}
}

// TestMaskOpenAIChatMultiChoiceOffset pins the per-choice `offset += len(content)`
// accumulator: a span that falls in the SECOND choice must be located using the
// cumulative offset of the first choice's content. Removing or inverting the
// self-assignment leaves offset at 0 and the second choice is never masked.
func TestMaskOpenAIChatMultiChoiceOffset(t *testing.T) {
	root := map[string]interface{}{
		"choices": []interface{}{
			map[string]interface{}{"delta": map[string]interface{}{"content": "AAAA"}},
			map[string]interface{}{"delta": map[string]interface{}{"content": "BBBB"}},
		},
	}
	// Concatenated carrier is "AAAABBBB"; the span [4,8) is the second choice.
	if applied := maskOpenAIChat(root, []engine.Finding{{Start: 4, End: 8}}); !applied {
		t.Fatal("expected mask applied to second choice")
	}
	choices := root["choices"].([]interface{})
	second := choices[1].(map[string]interface{})["delta"].(map[string]interface{})["content"]
	if second != "****" {
		t.Fatalf("second choice content = %q, want %q", second, "****")
	}
}

// TestMaskOpenAIChatAccumulatesOffsetAcrossChoices pins that offset is a RUNNING
// SUM across all prior choices, not each choice's own length in isolation. A
// two-choice fixture can't distinguish "offset += len(content)" from
// "offset = len(content)" when the first choice starts the loop at offset 0
// (both produce the same value after one iteration). A third choice exposes
// the difference: reaching it requires the sum of the first two lengths, not
// just the second choice's length.
func TestMaskOpenAIChatAccumulatesOffsetAcrossChoices(t *testing.T) {
	root := map[string]interface{}{
		"choices": []interface{}{
			map[string]interface{}{"delta": map[string]interface{}{"content": "AA"}},
			map[string]interface{}{"delta": map[string]interface{}{"content": "BBB"}},
			map[string]interface{}{"delta": map[string]interface{}{"content": "CCCC"}},
		},
	}
	// Concatenated carrier "AABBBCCCC" (len 9); span [5,9) is the whole third
	// choice. Reaching it needs offset = len("AA")+len("BBB") = 5, not 3.
	if applied := maskOpenAIChat(root, []engine.Finding{{Start: 5, End: 9}}); !applied {
		t.Fatal("expected mask applied to third choice")
	}
	choices := root["choices"].([]interface{})
	third := choices[2].(map[string]interface{})["delta"].(map[string]interface{})["content"]
	if third != "****" {
		t.Fatalf("third choice content = %q, want %q (offset must accumulate across all prior choices)", third, "****")
	}
}

// TestApplyMaskToEventPreservesTrailingFramingAfterContinuationLine pins that
// the rebuild loop SKIPS a dropped continuation `data:` line (continue) rather
// than stopping the whole rebuild (break). A multi-line data: payload's SSE
// framing includes trailing blank-line entries after the continuation line;
// stopping early would truncate the double-newline event terminator.
func TestApplyMaskToEventPreservesTrailingFramingAfterContinuationLine(t *testing.T) {
	raw := []byte("data: {\"choices\":[{\"delta\":{\"content\":\"TESTKEYABCDEFGHIJKLMNOP\"}}],\ndata: \"usage\":null}\n\n")
	evt := pendingEvent{raw: raw, decodedStart: 0, decodedEnd: 23}
	spans := []engine.Finding{{RuleID: "test-key", Start: 0, End: 23}}
	result := applyMaskToEvent(evt, spans, "/v1/chat/completions")
	if bytes.Contains(result, []byte("TESTKEY")) {
		t.Fatalf("secret must be masked, got %q", result)
	}
	if !bytes.HasSuffix(result, []byte("\n\n")) {
		t.Fatalf("SSE double-newline terminator after the dropped continuation line must be preserved, got %q", result)
	}
}

// --- streamScanner.finalize direct unit tests --------------------------------
//
// These construct a streamScanner directly (white-box, package gate) rather
// than driving it through a full HTTP round trip, so the guard conditions in
// finalize() can be pinned in isolation, including states the real
// newStreamScanner constructor never produces on its own (e.g. a non-nil
// streamScan with a nil eng) — the guard exists specifically to defend against
// exactly that combination regardless of how it arises.

func TestFinalizeSkipsTailFeedWhenAlreadyBlocked(t *testing.T) {
	m, err := engine.NewMatcher([]engine.Rule{{
		ID: "k", Class: "secret.test", Pattern: `AKIA[0-9A-Z]{16}`, MaxMatchLen: 20, Keywords: []string{"AKIA"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	secret := "AKIA" + strings.Repeat("A", 16)
	ss := &streamScanner{
		eng:              m,
		evaluator:        logOnlyEvaluator(),
		streamScan:       m.NewStreamScan(),
		decoded:          []byte(secret),
		feededDecodedLen: 0, // the whole buffer is still an unfed "tail"
		blocked:          true,
		seenUnscanned:    map[string]struct{}{},
	}
	var buf bytes.Buffer
	verdict, _, _ := ss.finalize(&buf)
	if verdict != ledger.VerdictBlocked {
		t.Fatalf("verdict = %q, want blocked", verdict)
	}
	if len(ss.allFindings) != 0 {
		t.Fatalf("finalize must not re-feed the tail once already blocked, got findings %+v", ss.allFindings)
	}
}

func TestFinalizeSkipsTailFeedWithNilEngine(t *testing.T) {
	m, err := engine.NewMatcher([]engine.Rule{{
		ID: "k", Class: "secret.test", Pattern: `AKIA[0-9A-Z]{16}`, MaxMatchLen: 20, Keywords: []string{"AKIA"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	secret := "AKIA" + strings.Repeat("A", 16)
	ss := &streamScanner{
		eng:              nil, // engine nil...
		evaluator:        logOnlyEvaluator(),
		streamScan:       m.NewStreamScan(), // ...but streamScan artificially non-nil
		decoded:          []byte(secret),
		feededDecodedLen: 0,
		blocked:          false,
		seenUnscanned:    map[string]struct{}{},
	}
	var buf bytes.Buffer
	verdict, _, _ := ss.finalize(&buf)
	if verdict != ledger.VerdictForwarded {
		t.Fatalf("verdict = %q, want forwarded (nil eng must skip tail feed even with non-nil streamScan)", verdict)
	}
	if len(ss.allFindings) != 0 {
		t.Fatalf("finalize must not feed the tail when eng is nil, got findings %+v", ss.allFindings)
	}
}

// TestFinalizeFeedsUnfedTailBeforeDraining pins the `feededDecodedLen <
// len(decoded)` guard: a secret sitting entirely in the never-fed tail must
// still be found. StreamScan.Finalize alone only drains candidates already
// registered by a prior Feed call — if the tail-feed step is skipped, a fresh
// StreamScan has no pending candidates to drain and the secret is missed
// entirely, not just delayed.
func TestFinalizeFeedsUnfedTailBeforeDraining(t *testing.T) {
	m, err := engine.NewMatcher([]engine.Rule{{
		ID: "k", Class: "secret.test", Pattern: `AKIA[0-9A-Z]{16}`, MaxMatchLen: 20, Keywords: []string{"AKIA"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	secret := "AKIA" + strings.Repeat("A", 16)
	ss := &streamScanner{
		eng:              m,
		evaluator:        logOnlyEvaluator(),
		streamScan:       m.NewStreamScan(),
		decoded:          []byte(secret),
		feededDecodedLen: 0,
		blocked:          false,
		seenUnscanned:    map[string]struct{}{},
	}
	var buf bytes.Buffer
	_, ledgerFindings, _ := ss.finalize(&buf)
	if len(ledgerFindings) != 1 || ledgerFindings[0].Class != "secret.test" {
		t.Fatalf("finalize must feed the never-fed tail before draining, got findings %+v", ledgerFindings)
	}
}

// --- log-only defensive branches (error paths) -------------------------------
//
// These pin defensive logging branches that fire only when a downstream write
// fails. Each captures log output (redirected for the test, restored after)
// rather than asserting on HTTP response bytes, since the branch's only
// observable effect is the log line.

type errWriter struct {
	http.ResponseWriter
}

func (e *errWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestResponseWriteErrorIsLogged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}
	gw, err := NewGateway(cfg, ledger.NewWriter(&bytes.Buffer{}), nil)
	if err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4"}`))
	w := &errWriter{ResponseWriter: httptest.NewRecorder()}
	gw.ServeHTTP(w, req)

	if !strings.Contains(logBuf.String(), "response write") {
		t.Fatalf("expected a logged response-write error, got log: %q", logBuf.String())
	}
}

type errLedgerWriter struct{}

func (errLedgerWriter) Write(p []byte) (int, error) {
	return 0, errors.New("ledger write failed")
}

func TestLedgerAppendErrorIsLoggedOnRequestPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}
	gw, err := NewGateway(cfg, ledger.NewWriter(errLedgerWriter{}), nil)
	if err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4"}`))
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, req)

	if !strings.Contains(logBuf.String(), "ledger:") {
		t.Fatalf("expected a logged ledger-append error, got log: %q", logBuf.String())
	}
}

func TestStreamLedgerAppendErrorIsLogged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
	}))
	defer upstream.Close()

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}
	gw, err := NewGateway(cfg, ledger.NewWriter(errLedgerWriter{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if !strings.Contains(logBuf.String(), "ledger:") {
		t.Fatalf("expected a logged ledger-append error on the streaming path, got log: %q", logBuf.String())
	}
}

// TestStreamingNonEOFReadErrorIsLogged forces an abrupt mid-stream connection
// close (hijack + close, no clean chunked terminator), which surfaces to the
// client as a non-io.EOF read error. Pins that the "err != io.EOF" guard
// actually discriminates: a clean end-of-stream must NOT log, but this must.
func TestStreamingNonEOFReadErrorIsLogged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		conn.Close()
	}))
	defer upstream.Close()

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}
	gw, err := NewGateway(cfg, ledger.NewWriter(&bytes.Buffer{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if !strings.Contains(logBuf.String(), "stream read error") {
		t.Fatalf("expected a logged non-EOF stream read error, got log: %q", logBuf.String())
	}
}

// TestApplyMaskToEventNonZeroDecodedStart pins the overlap-to-local offset math
// `overlapStart - evt.decodedStart` / `overlapEnd - evt.decodedStart` for an
// event that does NOT start at decoded offset 0.
func TestApplyMaskToEventNonZeroDecodedStart(t *testing.T) {
	evt := pendingEvent{
		raw:          []byte(`data: {"choices":[{"delta":{"content":"0123456789"}}]}` + "\n\n"),
		decodedStart: 5,
		decodedEnd:   15,
	}
	// Absolute mask span [7,10) -> local content offset [2,5): masks "234".
	spans := []engine.Finding{{Start: 7, End: 10}}
	result := applyMaskToEvent(evt, spans, "/v1/chat/completions")
	if !bytes.Contains(result, []byte("01***56789")) {
		t.Fatalf("expected content[2:5] masked, got %s", result)
	}
}

// --- pending event flushing -------------------------------------------------

func TestPopSafeEventsTable(t *testing.T) {
	cases := []struct {
		name       string
		pending    []pendingEvent
		safeEnd    int
		wantPopped int
		wantRemain int
	}{
		{"pops contiguous safe prefix", []pendingEvent{{decodedEnd: 2}, {decodedEnd: 4}}, 4, 2, 0},
		{"pops event ending exactly at safeEnd", []pendingEvent{{decodedEnd: 5}}, 5, 1, 0},
		{"stops at first unsafe event", []pendingEvent{{decodedEnd: 2}, {decodedEnd: 10}, {decodedEnd: 3}}, 5, 1, 2},
		{"nothing safe pops nothing", []pendingEvent{{decodedEnd: 10}}, 5, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ss := &streamScanner{pending: tc.pending}
			popped := ss.popSafeEvents(tc.safeEnd)
			if len(popped) != tc.wantPopped {
				t.Fatalf("popped = %d, want %d", len(popped), tc.wantPopped)
			}
			if len(ss.pending) != tc.wantRemain {
				t.Fatalf("remaining = %d, want %d", len(ss.pending), tc.wantRemain)
			}
		})
	}
}

// --- routing / model helpers ------------------------------------------------

func TestSplitPathTable(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		wantFirst string
		wantRest  string
	}{
		{"no slash after trim", "openai", "openai", "/"},
		{"slash splits first segment", "/openai/v1/chat", "openai", "/v1/chat"},
		{"trailing segment", "/anthropic/v1/messages", "anthropic", "/v1/messages"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, rest := splitPath(tc.path)
			if first != tc.wantFirst || rest != tc.wantRest {
				t.Fatalf("splitPath(%q) = (%q,%q), want (%q,%q)", tc.path, first, rest, tc.wantFirst, tc.wantRest)
			}
		})
	}
}

func TestExtractModelTable(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"valid model", `{"model":"gpt-4"}`, "gpt-4"},
		{"claude model", `{"model":"claude-3-opus"}`, "claude-3-opus"},
		{"no model field", `{"messages":[]}`, ""},
		{"invalid json", `not json`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractModel([]byte(tc.body)); got != tc.want {
				t.Fatalf("extractModel(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

// --- SSE tokenizer ----------------------------------------------------------

func TestReadSSEChunksFinalTokenWithoutTerminator(t *testing.T) {
	next := readSSEChunks(strings.NewReader("data: last"))
	_, tok, err := next()
	if string(tok) != "data: last" {
		t.Fatalf("final token = %q, want %q (err=%v)", tok, "data: last", err)
	}
}

func TestReadSSEChunksLeadingDoubleNewline(t *testing.T) {
	next := readSSEChunks(strings.NewReader("\n\nX\n\n"))
	_, tok, _ := next()
	if string(tok) != "\n\n" {
		t.Fatalf("first token = %q, want %q", tok, "\n\n")
	}
}

// errReader yields data on the first read, then a non-EOF error.
type errReader struct {
	data []byte
	done bool
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, errors.New("boom")
	}
	r.done = true
	return copy(p, r.data), nil
}

func TestReadSSEChunksNonEOFErrorDropsPartial(t *testing.T) {
	next := readSSEChunks(&errReader{data: []byte("data: partial")})
	_, tok, err := next()
	// A non-EOF error must surface with no salvaged token (the `err == io.EOF &&
	// len(buf) > 0` guard is a conjunction of EOF AND buffered data).
	if tok != nil {
		t.Fatalf("token = %q, want nil on non-EOF error", tok)
	}
	if err == nil || err == io.EOF {
		t.Fatalf("err = %v, want a non-EOF error", err)
	}
}

// --- streamScanner method-level ---------------------------------------------

func logOnlyEvaluator() *policy.Evaluator {
	return policy.NewEvaluator(&policy.Config{
		Defaults: policy.Defaults{Action: "log_only", OnError: "closed"},
	})
}

func TestScanAndFlushNilEngineFlushesPending(t *testing.T) {
	ss := newStreamScanner(nil, nil, "d", "/v1/chat/completions", "r")
	ss.addEvent([]byte("data: hello\n\n"), streamTextResult{text: "hello"})
	var buf bytes.Buffer
	ss.scanAndFlush(&buf)
	if !bytes.Contains(buf.Bytes(), []byte("data: hello")) {
		t.Fatalf("nil-engine scanner must flush pending, got %q", buf.String())
	}
}

func TestScanAndFlushFlushesSafeProse(t *testing.T) {
	m, err := engine.NewMatcher([]engine.Rule{{
		ID: "k", Class: "secret.test", Pattern: `AKIA[0-9A-Z]{16}`, MaxMatchLen: 20, Keywords: []string{"AKIA"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ss := newStreamScanner(m, logOnlyEvaluator(), "d", "/v1/chat/completions", "r")
	raw := []byte(`data: {"choices":[{"delta":{"content":"the quick brown fox"}}]}` + "\n\n")
	ss.addEvent(raw, streamTextResult{text: "the quick brown fox"})
	var buf bytes.Buffer
	ss.scanAndFlush(&buf)
	// Prose has no live anchor: hold is 0, safeEnd == len(decoded), the event
	// flushes. Clamping safeEnd to 0 would withhold everything.
	if buf.Len() == 0 {
		t.Fatal("prose event with hold 0 must be flushed, got empty output")
	}
}

// --- applyActions verdict ---------------------------------------------------

// TestApplyActionsMixedExemptionIsNotExempted pins the `allExempted && anyExempted`
// verdict conjunction. A finding mix where one class is exempt and one is not
// must NOT resolve to Exempted (only a wholly-exempt set does).
func TestApplyActionsMixedExemptionIsNotExempted(t *testing.T) {
	cfg := &policy.Config{
		Defaults:   policy.Defaults{Action: "log_only", OnError: "closed"},
		Exemptions: []policy.Exemption{{Class: "secret.a", Destination: "dest1"}},
	}
	g := &Gateway{evaluator: policy.NewEvaluator(cfg)}
	findings := []engine.Finding{
		{RuleID: "ra", Class: "secret.a", Confidence: 1.0},
		{RuleID: "rb", Class: "secret.b", Confidence: 1.0},
	}
	w := httptest.NewRecorder()
	verdict, _, _ := g.applyActions("r", "request", []byte("body"), findings, "dest1", "/v1/chat/completions", w)
	if verdict != ledger.VerdictForwarded {
		t.Fatalf("mixed exemption verdict = %q, want forwarded (not exempted)", verdict)
	}
}

func TestApplyActionsAllExemptedIsExempted(t *testing.T) {
	cfg := &policy.Config{
		Defaults: policy.Defaults{Action: "log_only", OnError: "closed"},
		Exemptions: []policy.Exemption{
			{Class: "secret.a", Destination: "dest1"},
			{Class: "secret.b", Destination: "dest1"},
		},
	}
	g := &Gateway{evaluator: policy.NewEvaluator(cfg)}
	findings := []engine.Finding{
		{RuleID: "ra", Class: "secret.a", Confidence: 1.0},
		{RuleID: "rb", Class: "secret.b", Confidence: 1.0},
	}
	w := httptest.NewRecorder()
	verdict, _, _ := g.applyActions("r", "request", []byte("body"), findings, "dest1", "/v1/chat/completions", w)
	if verdict != ledger.VerdictExempted {
		t.Fatalf("all-exempt verdict = %q, want exempted", verdict)
	}
}

// --- streaming loop control (integration) -----------------------------------

func TestStreamingForwardsFinalEventWithoutTerminator(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"AAA\"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"BBB\"}}]}"))
	}))
	defer upstream.Close()

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}
	gw, err := NewGateway(cfg, ledger.NewWriter(&bytes.Buffer{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("BBB")) {
		t.Fatalf("final unterminated event must be forwarded, got %q", body)
	}
}

func TestStreamingForwardsEventAfterDONE(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"AAA\"}}]}\n\n"))
		w.Write([]byte("data: [DONE]\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"BBB\"}}]}\n\n"))
	}))
	defer upstream.Close()

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}
	gw, err := NewGateway(cfg, ledger.NewWriter(&bytes.Buffer{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// The [DONE] sentinel is forwarded like any other control event (D-20
	// byte-identical passthrough — real client SDKs key off it to detect
	// stream completion) and must not stop the loop: the event after it
	// must still arrive too.
	if !bytes.Contains(body, []byte("[DONE]")) {
		t.Fatalf("[DONE] sentinel must be forwarded to the client, got %q", body)
	}
	if !bytes.Contains(body, []byte("BBB")) {
		t.Fatalf("event after [DONE] must be forwarded, got %q", body)
	}
}
