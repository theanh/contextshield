package gate

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/theanh/contextshield/engine"
	"github.com/theanh/contextshield/ledger"
	"github.com/theanh/contextshield/policy"
)

func TestStreamingPassthroughNoFindings(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\ndata: [DONE]\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %q", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "Hello") || !strings.Contains(string(body), "world") {
		t.Fatalf("streaming content should be forwarded: %q", body)
	}

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var responseEntry ledger.Entry
	for _, line := range lines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
			responseEntry = entry
			break
		}
	}
	if responseEntry.Verdict != ledger.VerdictForwarded {
		t.Fatalf("expected forwarded verdict, got %q", responseEntry.Verdict)
	}
}

func TestStreamingResponseNoLongerReturnsUnsupportedError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: hello\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusBadGateway {
		t.Fatalf("streaming unsupported error should be gone, got 502: %q", body)
	}
	if strings.Contains(string(body), "streaming_response_unsupported") {
		t.Fatalf("streaming unsupported error should not appear: %q", body)
	}
}

func TestStreamingBlockDetectsSecretAndEmitsSSEError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"The key is TESTKEYABCDEFGHIJKLMNOP\"}}]}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "block"}},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// SSE streaming: status is 200 (can't change mid-stream), block is an SSE error event
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for SSE stream with block error event, got %d: %q", resp.StatusCode, body)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "contextshield_blocked") {
		t.Fatalf("expected contextshield_blocked in SSE error event, got %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "event: error") {
		t.Fatalf("expected 'event: error' SSE error, got %q", bodyStr)
	}
	if strings.Contains(bodyStr, "TESTKEYABCDEFGHIJKLMNOP") {
		t.Fatal("blocked response must not contain the matched value")
	}

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var responseEntry ledger.Entry
	for _, line := range lines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
			responseEntry = entry
			break
		}
	}
	if responseEntry.Verdict != ledger.VerdictBlocked {
		t.Fatalf("expected blocked verdict, got %q", responseEntry.Verdict)
	}
}

func TestStreamingLogOnlyForwardsAndRecordsFindings(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"safe text\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" TESTKEYABCDEFGHIJKLMNOP \"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" more text\"}}]}\n\ndata: [DONE]\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %q", resp.StatusCode, body)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "safe text") || !strings.Contains(bodyStr, "more text") {
		t.Fatalf("log_only should forward content, got %q", bodyStr)
	}

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var responseEntry ledger.Entry
	for _, line := range lines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
			responseEntry = entry
			break
		}
	}
	if responseEntry.Verdict != ledger.VerdictForwarded {
		t.Fatalf("expected forwarded verdict for log_only, got %q", responseEntry.Verdict)
	}
	foundTestKey := false
	for _, f := range responseEntry.Findings {
		if f.Class == "secret.test_key" && f.Action == "log_only" && f.Count > 0 {
			foundTestKey = true
		}
	}
	if !foundTestKey {
		t.Fatalf("expected log_only finding for secret.test_key, got %+v", responseEntry.Findings)
	}
}

func TestStreamingSplitSecretAcrossChunksDetected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"The key is TEST\"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"KEYABCDEFGHIJKLMNOP\"}}]}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %q", resp.StatusCode, body)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "TEST") || !strings.Contains(bodyStr, "KEYABCDEFGHIJKLMNOP") {
		t.Fatalf("log_only should forward split secret events, got %q", bodyStr)
	}

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var responseEntry ledger.Entry
	for _, line := range lines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
			responseEntry = entry
			break
		}
	}
	foundTestKey := false
	for _, f := range responseEntry.Findings {
		if f.Class == "secret.test_key" && f.Action == "log_only" && f.Count > 0 {
			foundTestKey = true
		}
	}
	if !foundTestKey {
		t.Fatalf("expected finding for split secret, got %+v", responseEntry.Findings)
	}
}

func TestStreamingBlockOnSplitSecretDetectedAcrossChunks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"The key is TESTKEYAB\"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"CDEFGHIJKLMNOP\"}}]}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "block"}},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for SSE stream, got %d: %q", resp.StatusCode, body)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "contextshield_blocked") {
		t.Fatalf("expected contextshield_blocked block event for split secret, got %q", bodyStr)
	}
	if strings.Contains(bodyStr, "TESTKEYABCDEFGHIJKLMNOP") {
		t.Fatal("block error must not contain matched value")
	}

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var responseEntry ledger.Entry
	for _, line := range lines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
			responseEntry = entry
			break
		}
	}
	if responseEntry.Verdict != ledger.VerdictBlocked {
		t.Fatalf("expected blocked verdict, got %q", responseEntry.Verdict)
	}
}

func TestStreamingMaskInStream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"safe \"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"TESTKEYABCDEFGHIJKLMNOP\"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\" more\"}}]}\n\ndata: [DONE]\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "mask"}},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for mask, got %d: %q", resp.StatusCode, body)
	}
	bodyStr := string(body)
	if strings.Contains(bodyStr, "TESTKEYABCDEFGHIJKLMNOP") {
		t.Fatalf("masked response should not contain original value: %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "safe ") || !strings.Contains(bodyStr, " more") {
		t.Fatalf("unmatched parts should be preserved: %q", bodyStr)
	}

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var responseEntry ledger.Entry
	for _, line := range lines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
			responseEntry = entry
			break
		}
	}
	if responseEntry.Verdict != ledger.VerdictMasked {
		t.Fatalf("expected masked verdict, got %q", responseEntry.Verdict)
	}
}

func TestStreamingCrossEventMaskDetected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"TESTKEYAB\"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"CDEFGHIJKLMNOP\"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\" more\"}}]}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "mask"}},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for mask, got %d: %q", resp.StatusCode, body)
	}
	bodyStr := string(body)
	if strings.Contains(bodyStr, "TESTKEYABCDEFGHIJKLMNOP") {
		t.Fatalf("masked cross-event secret must not appear in output: %q", bodyStr)
	}
	if !strings.Contains(bodyStr, " more") {
		t.Fatalf("unmasked trailing events should be preserved: %q", bodyStr)
	}

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var responseEntry ledger.Entry
	for _, line := range lines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
			responseEntry = entry
			break
		}
	}
	if responseEntry.Verdict != ledger.VerdictMasked {
		t.Fatalf("expected masked verdict for cross-event mask, got %q", responseEntry.Verdict)
	}
}

// TestStreamingMaskSplitSecretPrefixNotLeaked guards the hold-back leak: a
// masked secret split across THREE events, where the rule's max_match_len
// window only completes on the final event, must not flush the earlier
// events' bytes in the clear. The prior windowEnd-currentEnd hold under-held
// once more than half the window had arrived, so event 1 ("TESTKEYABCDEFGH")
// was flushed unmasked while scanning event 2. A 2-event split can't expose
// this — its window completes on event 2 and resolves immediately, so the
// buggy hold still (accidentally) clamps safeEnd to 0.
func TestStreamingMaskSplitSecretPrefixNotLeaked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"TESTKEYABCDEFGH\"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"IJKLMN\"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"OP\"}}]}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "mask"}},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %q", resp.StatusCode, body)
	}
	bodyStr := string(body)
	// The secret prefix must never appear in the clear — not the full value,
	// and not the "TESTKEY" anchor from event 1's held-back content.
	if strings.Contains(bodyStr, "TESTKEY") {
		t.Fatalf("split-secret prefix leaked unmasked: %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "*") {
		t.Fatalf("expected masked output, got %q", bodyStr)
	}

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var responseEntry ledger.Entry
	for _, line := range lines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
			responseEntry = entry
			break
		}
	}
	if responseEntry.Verdict != ledger.VerdictMasked {
		t.Fatalf("expected masked verdict, got %q", responseEntry.Verdict)
	}
}

// TestStreamingBlockResolvedAtFinalizeWithholdsAndEmitsError covers a
// block-action secret that only resolves in StreamScan.Finalize: the rule's
// max_match_len (40) is larger than the secret, so the AC-out candidate stays
// pending through every Feed (its window never fully arrives) and is drained
// only at end-of-stream. Previously the final drain skipped block detection, so
// the secret was neither blocked nor masked — it flushed in the clear and the
// stream was logged as forwarded. It must now be withheld, ledgered as blocked,
// and surfaced to the client as a contextshield_blocked event.
func TestStreamingBlockResolvedAtFinalizeWithholdsAndEmitsError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"TESTKEYABCDEFGHIJKLMNOP\"}}]}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 40, // > secret length, so it stays pending until Finalize
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "block"}},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for SSE stream, got %d: %q", resp.StatusCode, body)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "contextshield_blocked") {
		t.Fatalf("expected contextshield_blocked event for finalize-time block, got %q", bodyStr)
	}
	if strings.Contains(bodyStr, "TESTKEY") {
		t.Fatalf("finalize-time blocked secret leaked in the clear: %q", bodyStr)
	}

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var responseEntry ledger.Entry
	for _, line := range lines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
			responseEntry = entry
			break
		}
	}
	if responseEntry.Verdict != ledger.VerdictBlocked {
		t.Fatalf("expected blocked verdict for finalize-time block, got %q", responseEntry.Verdict)
	}
}

// TestStreamingMaskMultiLineDataEvent covers a secret carried in a multi-line
// `data:` payload (valid per the SSE spec: data lines are joined with '\n').
// parseSSEToken already joins them for scanning; masking must reconstruct the
// same payload. The prior extractDataLine took only the first data line — an
// invalid JSON fragment — so maskProviderData failed and the event was
// forwarded raw, leaking the secret. It must now be masked.
func TestStreamingMaskMultiLineDataEvent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		// One SSE event, JSON split across two data: lines at a field boundary.
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"TESTKEYABCDEFGHIJKLMNOP\"}}],\ndata: \"usage\":null}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "mask"}},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %q", resp.StatusCode, body)
	}
	bodyStr := string(body)
	if strings.Contains(bodyStr, "TESTKEY") {
		t.Fatalf("secret in multi-line data event leaked unmasked: %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "*") {
		t.Fatalf("expected masked output, got %q", bodyStr)
	}
	// The masked event must still parse as one JSON object with the carrier
	// masked — prove the rebuild produced valid provider JSON.
	dataLine := ""
	for _, line := range strings.Split(bodyStr, "\n") {
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, "choices") {
			dataLine = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if dataLine == "" {
		t.Fatalf("no masked data line in output: %q", bodyStr)
	}
	var parsed struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(dataLine), &parsed); err != nil {
		t.Fatalf("masked data line is not valid JSON: %v (%q)", err, dataLine)
	}
	if len(parsed.Choices) != 1 || parsed.Choices[0].Delta.Content != strings.Repeat("*", 23) {
		t.Fatalf("carrier not fully masked: %+v", parsed)
	}

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var responseEntry ledger.Entry
	for _, line := range lines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
			responseEntry = entry
			break
		}
	}
	if responseEntry.Verdict != ledger.VerdictMasked {
		t.Fatalf("expected masked verdict, got %q", responseEntry.Verdict)
	}
}

func TestStreamingAnthropicContentBlockDelta(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n"))
		w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n\n"))
		w.Write([]byte("event: message_done\ndata: {}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"anthropic": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/anthropic/v1/messages", "application/json",
		bytes.NewReader([]byte(`{"model":"claude-3"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %q", resp.StatusCode, body)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "Hello") || !strings.Contains(bodyStr, "world") {
		t.Fatalf("anthropic SSE content should be forwarded: %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "content_block_delta") {
		t.Fatalf("SSE event type should be preserved: %q", bodyStr)
	}
}

func TestStreamingErrorPathEmitsLedger(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"part1\"}}]}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from streaming, got %d: %q", resp.StatusCode, body)
	}

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var responseEntry ledger.Entry
	for _, line := range lines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
			responseEntry = entry
			break
		}
	}
	if responseEntry.Verdict != ledger.VerdictForwarded {
		t.Fatalf("expected forwarded verdict for clean stream, got %q", responseEntry.Verdict)
	}
	_ = body
}

func TestStreamingScannerConstructor(t *testing.T) {
	ss := newStreamScanner(nil, nil, "api.test.com", "/v1/chat/completions", "r_test")
	if ss == nil {
		t.Fatal("expected non-nil scanner")
	}
	if ss.streamScan != nil {
		t.Fatalf("expected nil streamScan with nil engine, got %v", ss.streamScan)
	}
}

func TestStreamingMaskEventPreservesSSEStructure(t *testing.T) {
	raw := []byte("data: {\"choices\":[{\"delta\":{\"content\":\"TESTKEYABCDEFGHIJKLMNOP\"}}]}\n\n")
	evt := pendingEvent{
		raw:          raw,
		decodedStart: 0,
		decodedEnd:   23,
	}
	spans := []engine.Finding{{
		RuleID: "test-key",
		Start:  0,
		End:    23,
	}}

	result := applyMaskToEvent(evt, spans, "/v1/chat/completions")
	if bytes.Equal(result, raw) {
		t.Fatal("masked event should differ from original")
	}
	if bytes.Contains(result, []byte("TESTKEYABCDEFGHIJKLMNOP")) {
		t.Fatal("masked result should not contain original value")
	}
	if !bytes.HasPrefix(result, []byte("data: ")) {
		t.Fatal("SSE data: prefix must be preserved")
	}
	if !bytes.HasSuffix(result, []byte("\n\n")) {
		t.Fatal("SSE double-newline must be preserved")
	}
}

func TestMaskToEventPartialOverlap(t *testing.T) {
	raw := []byte("data: {\"choices\":[{\"delta\":{\"content\":\"TESTKEYAB\"}}]}\n\n")
	evt := pendingEvent{
		raw:          raw,
		decodedStart: 0,
		decodedEnd:   9,
	}
	spans := []engine.Finding{{
		RuleID: "test-key",
		Start:  0,
		End:    23,
	}}

	result := applyMaskToEvent(evt, spans, "/v1/chat/completions")
	if bytes.Equal(result, raw) {
		t.Fatal("partial-overlap mask should modify event")
	}
	if bytes.Contains(result, []byte("TESTKEYAB")) {
		t.Fatal("partial-overlap mask should mask the overlapping portion")
	}
	if !bytes.HasPrefix(result, []byte("data: ")) {
		t.Fatal("SSE prefix must be preserved")
	}
	if !bytes.HasSuffix(result, []byte("\n\n")) {
		t.Fatal("SSE suffix must be preserved")
	}
}

func TestStreamingBlockTruncatesStream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"safe \"}}]}\n\n"))
		// Trailing space after the key: in the concatenated decoded stream the
		// key must be token-bounded for \bTESTKEY…\b to match (gluing the next
		// event's word chars directly onto it would make it a longer,
		// non-matching run — the correct boundary semantics after the
		// candidate-window fix, D-26).
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"TESTKEYABCDEFGHIJKLMNOP \"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"should not appear\"}}]}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "block"}},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for SSE stream, got %d: %q", resp.StatusCode, body)
	}
	bodyStr := string(body)
	if strings.Contains(bodyStr, "should not appear") {
		t.Fatal("truncated stream should not include events after the block")
	}
	if !strings.Contains(bodyStr, "contextshield_blocked") {
		t.Fatalf("expected block error event in stream, got %q", bodyStr)
	}
}

func TestStreamingUnscannedFieldsLedgered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}],\"unknown_field\":\"value\"}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	io.ReadAll(resp.Body)

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var responseEntry ledger.Entry
	for _, line := range lines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
			responseEntry = entry
			break
		}
	}
	if len(responseEntry.UnscannedFields) == 0 {
		t.Fatalf("expected unscanned fields in ledger, got %+v", responseEntry.UnscannedFields)
	}
}

// TestStreamingSSECommentFlaggedUnscanned pins that a non-empty SSE comment
// line (`: <text>`) is flagged via unscanned_fields (matching the D-21
// pattern for adapter-unrecognized JSON fields), since parseSSEToken has no
// field that captures or scans comment text — the D-20 byte-identical
// passthrough guarantee only covers recognized event/data content. A routine
// empty keep-alive ping (`: \n`, common on long-lived connections) must NOT
// be flagged: it carries no bytes that could be anything, and flagging every
// keep-alive would just be ledger noise.
func TestStreamingSSECommentFlaggedUnscanned(t *testing.T) {
	cases := []struct {
		name          string
		commentLine   string
		wantUnscanned bool
	}{
		{"non-empty comment is flagged", ": some payload here\n\n", true},
		{"empty keep-alive is not flagged", ": \n\n", false},
		{"bare colon keep-alive is not flagged", ":\n\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
				w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n"))
				w.Write([]byte(tc.commentLine))
			}))
			defer upstream.Close()

			var ledgerBuf bytes.Buffer
			lw := ledger.NewWriter(&ledgerBuf)
			eng, err := engine.NewMatcher([]engine.Rule{{
				ID:          "test-key",
				Class:       "secret.test_key",
				Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
				MaxMatchLen: 23,
				Keywords:    []string{"TESTKEY"},
			}})
			if err != nil {
				t.Fatal(err)
			}
			cfg := &policy.Config{
				Listen:    ":0",
				Upstreams: map[string]string{"test": upstream.URL},
				Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
			}
			gw, err := NewGateway(cfg, lw, eng)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(gw)
			defer server.Close()

			resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
				bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			io.ReadAll(resp.Body)

			lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
			var responseEntry ledger.Entry
			for _, line := range lines {
				var entry ledger.Entry
				if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "response" {
					responseEntry = entry
					break
				}
			}
			gotUnscanned := len(responseEntry.UnscannedFields) > 0
			if gotUnscanned != tc.wantUnscanned {
				t.Fatalf("unscanned_fields present = %v, want %v (got %+v)", gotUnscanned, tc.wantUnscanned, responseEntry.UnscannedFields)
			}
		})
	}
}

func TestStreamingBlockPreventsDownstreamEvents(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		// Trailing space so the key is token-bounded in the concatenated
		// decoded stream (see the D-26 note in TestStreamingBlockTruncatesStream);
		// the block must still truncate the following "more data" event.
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"TESTKEYABCDEFGHIJKLMNOP \"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"more data\"}}]}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "block"}},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "more data") {
		t.Fatal("blocked stream should truncate; downstream events must not appear")
	}
}

// TestStreamingZeroContentControlEventDoesNotLeakPendingSecret pins a fix to
// a masking-bypass regression: a real engine.Matcher (unlike
// TestStreamingForwardsEventAfterDONE's eng=nil, which never exercises this
// path) scans a secret split across events with a zero-decoded-content
// control event (an SSE keep-alive with no `data:` line — structurally
// identical to the OpenAI `[DONE]` sentinel) landing in the MIDDLE, before
// the completing chunk arrives. engine.StreamScan.Feed's empty-chunk fast
// path used to unconditionally return holdLen=0, discarding the still-live
// pending-candidate state; scanAndFlush then computed safeEnd as the full
// buffer and flushed the not-yet-resolved secret prefix to the client BEFORE
// the completing chunk ever proved it was a real secret and triggered the
// block. The fix (engine/engine.go Feed) recomputes holdLen from current
// state on an empty chunk instead of hardcoding 0. Grade the outcome: the
// raw secret must never reach the client, whether whole or as an unblocked
// prefix — only the block event may carry evidence of it.
func TestStreamingZeroContentControlEventDoesNotLeakPendingSecret(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		flusher := w.(http.Flusher)
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"the key is AKIAIOSFODNN7EX\"}}]}\n\n"))
		flusher.Flush()
		w.Write([]byte(": keep-alive\n\n"))
		flusher.Flush()
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"AMPLE done\"}}]}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "aws-access-key-id",
		Class:       "secret.aws_access_key",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "block"}},
	}
	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	// The block event carries only the class/rule_id/request_id, never the
	// matched value (Invariant 1) — so ANY occurrence of the secret's
	// characters in the response body is a content leak, regardless of
	// whether a block event also fires. A `&& !contains("contextshield_
	// blocked")` escape hatch here would be wrong: the buggy version leaked
	// the held prefix as content AND still emitted the block once the
	// completing chunk resolved the match, so gating the leak check on
	// "block absent" lets exactly the bug this test exists to catch slip
	// through. Assert the prefix never appears, full stop.
	if strings.Contains(bodyStr, "AKIAIOSFODNN7EX") {
		t.Fatalf("secret (or its held prefix) leaked into the response body — the block event never carries the value, so this is a content leak: %q", bodyStr)
	}
}

func TestStreamingPassthroughOnResponsesEndpoint(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello world\"}\n\n"))
		w.Write([]byte("event: response.done\ndata: {}\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"openai": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/openai/v1/responses", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4o"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %q", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "Hello world") {
		t.Fatalf("response streaming should forward content: %q", body)
	}
}
