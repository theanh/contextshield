package gate

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/theanh/contextshield/engine"
	"github.com/theanh/contextshield/ledger"
	"github.com/theanh/contextshield/policy"
)

func TestByteIdenticalPassthrough(t *testing.T) {
	var reqBody, respBody []byte

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		reqBody = body
		w.Write(body)
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	cfg := &policy.Config{
		Listen: ":0",
		Upstreams: map[string]string{
			"test": upstream.URL,
		},
		Defaults: policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	input := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`)
	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	output, _ := io.ReadAll(resp.Body)

	if !bytes.Equal(input, output) {
		t.Fatalf("byte mismatch:\ninput:  %q\noutput: %q", input, output)
	}
	if !bytes.Equal(input, reqBody) {
		t.Fatalf("upstream received different bytes:\nsent:    %q\nupstream: %q", input, reqBody)
	}
	respBody = output
	if !bytes.Equal(respBody, reqBody) {
		t.Fatalf("response != upstream echo:\nupstream: %q\nresponse: %q", reqBody, respBody)
	}

	if ledgerBuf.Len() == 0 {
		t.Fatal("expected ledger output, got empty")
	}

	lines := strings.TrimSpace(ledgerBuf.String())
	lineCount := len(strings.Split(lines, "\n"))
	if lineCount < 1 {
		t.Fatalf("expected at least 1 ledger line, got %d", lineCount)
	}
}

func TestGzipResponseBytesPreserved(t *testing.T) {
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write([]byte("upstream bytes that must stay compressed")); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	compressedBody := compressed.Bytes()
	var upstreamAcceptEncoding string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusAccepted)
		w.Write(compressedBody)
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	cfg := &policy.Config{
		Listen: ":0",
		Upstreams: map[string]string{
			"test": upstream.URL,
		},
		Defaults: policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	output, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if upstreamAcceptEncoding != "" {
		t.Fatalf("gateway requested transparent encoding from upstream: %q", upstreamAcceptEncoding)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected %d, got %d", http.StatusAccepted, resp.StatusCode)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected gzip content encoding, got %q", resp.Header.Get("Content-Encoding"))
	}
	if !bytes.Equal(output, compressedBody) {
		t.Fatalf("response bytes changed:\nupstream: %x\nclient:   %x", compressedBody, output)
	}
}

func TestHopByHopHeadersRemovedInBothDirections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	upstreamRequestCh := make(chan http.Header, 1)
	upstreamErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			upstreamErrCh <- err
			return
		}
		defer conn.Close()

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			upstreamErrCh <- err
			return
		}
		upstreamRequestCh <- req.Header.Clone()
		io.Copy(io.Discard, req.Body)
		req.Body.Close()

		io.WriteString(conn, "HTTP/1.1 200 OK\r\nConnection: X-Upstream-Hop\r\nX-Upstream-Hop: remove\r\nKeep-Alive: timeout=5\r\nProxy-Connection: keep-alive\r\nContent-Length: 2\r\n\r\nok")
	}()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	cfg := &policy.Config{
		Listen: ":0",
		Upstreams: map[string]string{
			"test": "http://" + listener.Addr().String(),
		},
		Defaults: policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	req.Header.Set("Connection", "X-Remove-Me, keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Te", "trailers")
	req.Header.Set("X-Remove-Me", "remove")

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	}

	var upstreamRequest http.Header
	select {
	case upstreamRequest = <-upstreamRequestCh:
	case err := <-upstreamErrCh:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for upstream request")
	}

	if upstreamRequest.Get("Connection") != "" {
		t.Fatalf("upstream received Connection header: %q", upstreamRequest.Get("Connection"))
	}
	if upstreamRequest.Get("Keep-Alive") != "" {
		t.Fatalf("upstream received Keep-Alive header: %q", upstreamRequest.Get("Keep-Alive"))
	}
	if upstreamRequest.Get("Te") != "" {
		t.Fatalf("upstream received Te header: %q", upstreamRequest.Get("Te"))
	}
	if upstreamRequest.Get("X-Remove-Me") != "" {
		t.Fatalf("upstream received Connection-named header: %q", upstreamRequest.Get("X-Remove-Me"))
	}
	if resp.Header.Get("Connection") != "" {
		t.Fatalf("client received Connection header: %q", resp.Header.Get("Connection"))
	}
	if resp.Header.Get("Keep-Alive") != "" {
		t.Fatalf("client received Keep-Alive header: %q", resp.Header.Get("Keep-Alive"))
	}
	if resp.Header.Get("Proxy-Connection") != "" {
		t.Fatalf("client received Proxy-Connection header: %q", resp.Header.Get("Proxy-Connection"))
	}
	if resp.Header.Get("X-Upstream-Hop") != "" {
		t.Fatalf("client received Connection-named response header: %q", resp.Header.Get("X-Upstream-Hop"))
	}
}

func TestMultiUpstreamPathRouting(t *testing.T) {
	openai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("openai"))
	}))
	defer openai.Close()

	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("anthropic"))
	}))
	defer anthropic.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	cfg := &policy.Config{
		Listen: ":0",
		Upstreams: map[string]string{
			"openai":    openai.URL,
			"anthropic": anthropic.URL,
		},
		Defaults: policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, _ := NewGateway(cfg, lw, nil)
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, _ := http.Post(server.URL+"/openai/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "openai" {
		t.Fatalf("expected openai response, got %q", body)
	}

	resp, _ = http.Post(server.URL+"/anthropic/v1/messages", "application/json",
		bytes.NewReader([]byte(`{"model":"claude-3"}`)))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "anthropic" {
		t.Fatalf("expected anthropic response, got %q", body)
	}
}

func TestSingleUpstreamNamedPrefixRouting(t *testing.T) {
	var upstreamPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	cfg := &policy.Config{
		Listen: ":0",
		Upstreams: map[string]string{
			"openai": upstream.URL,
		},
		Defaults: policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/openai/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if upstreamPath != "/v1/chat/completions" {
		t.Fatalf("expected stripped upstream path /v1/chat/completions, got %q", upstreamPath)
	}
}

func TestLedgerError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("closed upstream should not receive a request")
	}))
	upstreamURL := upstream.URL
	upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	cfg := &policy.Config{
		Listen: ":0",
		Upstreams: map[string]string{
			"test": upstreamURL,
		},
		Defaults: policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, _ := NewGateway(cfg, lw, nil)
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}

	lines := strings.TrimSpace(ledgerBuf.String())
	entries := strings.Split(lines, "\n")
	if len(entries) != 1 {
		t.Fatalf("expected only the failed request crossing in ledger, got %d lines: %s", len(entries), lines)
	}

	var entry ledger.Entry
	if err := json.Unmarshal([]byte(entries[0]), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Direction != "request" {
		t.Fatalf("expected request direction, got %q", entry.Direction)
	}
	if entry.Verdict != ledger.VerdictError {
		t.Fatalf("expected error verdict, got %q", entry.Verdict)
	}
	if strings.Contains(lines, `"verdict":"forwarded"`) {
		t.Fatalf("failed crossing should not be recorded as forwarded: %s", lines)
	}
}

func TestStreamingResponseForwardsWithNoEngine(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Write([]byte("data: hello\n\n"))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	cfg := &policy.Config{
		Listen: ":0",
		Upstreams: map[string]string{
			"test": upstream.URL,
		},
		Defaults: policy.Defaults{Action: "log_only", OnError: "closed"},
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for streaming passthrough, got %d with %q", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "data: hello") {
		t.Fatalf("expected SSE data forwarded, got %q", body)
	}

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected request + response ledger lines, got %d: %s", len(lines), ledgerBuf.String())
	}

	var requestEntry ledger.Entry
	if err := json.Unmarshal([]byte(lines[0]), &requestEntry); err != nil {
		t.Fatal(err)
	}
	if requestEntry.Direction != "request" || requestEntry.Verdict != ledger.VerdictForwarded {
		t.Fatalf("expected forwarded request ledger line, got: %s", lines[0])
	}

	var responseEntry ledger.Entry
	if err := json.Unmarshal([]byte(lines[1]), &responseEntry); err != nil {
		t.Fatal(err)
	}
	if responseEntry.Direction != "response" || responseEntry.Verdict != ledger.VerdictForwarded {
		t.Fatalf("expected forwarded response ledger line, got: %s", lines[1])
	}
}

func TestLedgerEntryShape(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"msg_123"}`))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, _ := NewGateway(cfg, lw, nil)
	server := httptest.NewServer(gw)
	defer server.Close()

	http.Post(server.URL+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4"}`)))

	lines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 ledger lines (request + response), got %d", len(lines))
	}

	for _, line := range lines {
		if !strings.Contains(line, `"req_id":"r_`) {
			t.Fatalf("ledger line missing req_id: %s", line)
		}
		if !strings.Contains(line, `"findings":[]`) {
			t.Fatalf("ledger line missing findings: %s", line)
		}
		if !strings.Contains(line, `"body_sha256"`) {
			t.Fatalf("ledger line missing body_sha256: %s", line)
		}
		if strings.Contains(line, `"policy_rev"`) {
			t.Fatalf("ledger line should omit policy_rev until real revisions exist: %s", line)
		}
	}

	if !strings.Contains(lines[0], `"direction":"request"`) {
		t.Fatalf("first line should be request: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"direction":"response"`) {
		t.Fatalf("second line should be response: %s", lines[1])
	}
}

func TestBlockRequestOpenAIErrorShape(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("blocked request must not reach upstream")
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

	input := `{"model":"gpt-4","messages":[{"role":"user","content":"key is TESTKEYABCDEFGHIJKLMNOP"}]}`
	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "contextshield_blocked") {
		t.Fatalf("expected contextshield_blocked code, got %q", body)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	errObj, ok := parsed["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected OpenAI error shape, got %+v", parsed)
	}
	if code, _ := errObj["code"].(string); code != "contextshield_blocked" {
		t.Fatalf("error code: expected contextshield_blocked, got %q", code)
	}
	detail, ok := errObj["detail"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing detail in error: %+v", errObj)
	}
	if detail["class"] != "secret.test_key" {
		t.Fatalf("expected class secret.test_key, got %v", detail["class"])
	}
	if detail["rule_id"] != "test-key" {
		t.Fatalf("expected rule_id test-key, got %v", detail["rule_id"])
	}

	if strings.Contains(string(body), "TESTKEY") {
		t.Fatal("block error must never contain matched value")
	}

	ledgerLines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	if len(ledgerLines) < 1 {
		t.Fatal("expected ledger output")
	}
	var entry ledger.Entry
	if err := json.Unmarshal([]byte(ledgerLines[0]), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Verdict != ledger.VerdictBlocked {
		t.Fatalf("expected blocked verdict, got %q", entry.Verdict)
	}
	if len(entry.Findings) == 0 {
		t.Fatal("expected findings in ledger entry")
	}
}

func TestBlockRequestScansDecodedKnownTextFields(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("blocked request must not reach upstream")
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

	input := `{"model":"gpt-4","messages":[{"role":"user","content":"key is AKIA\u0049OSFODNN7EXAMPLE"}]}`
	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected escaped decoded secret to block, got %d with %q", resp.StatusCode, body)
	}
}

func TestRequestScanIgnoresKnownStructuralFields(t *testing.T) {
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
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

	input := []byte(`{"model":"AKIAIOSFODNN7EXAMPLE","messages":[{"role":"AKIAIOSFODNN7EXAMPLE","content":[{"type":"AKIAIOSFODNN7EXAMPLE"}]}]}`)
	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("structural fields should not block, got %d with %q", resp.StatusCode, body)
	}
	if !bytes.Equal(upstreamBody, input) {
		t.Fatalf("request body changed:\ninput:    %q\nupstream: %q", input, upstreamBody)
	}
}

func TestUnknownRequestFieldsAreLedgeredAsUnscanned(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
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
		strings.NewReader(`{"model":"gpt-4","messages":[],"new_provider_text":"AKIAIOSFODNN7EXAMPLE"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unknown fields are visible fail-open by default, got %d with %q", resp.StatusCode, body)
	}

	ledgerLines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var requestEntry ledger.Entry
	for _, line := range ledgerLines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "request" {
			requestEntry = entry
			break
		}
	}
	if len(requestEntry.UnscannedFields) != 1 || requestEntry.UnscannedFields[0] != "$.new_provider_text" {
		t.Fatalf("expected unknown field in ledger, got %+v", requestEntry.UnscannedFields)
	}
	if len(requestEntry.Findings) != 0 {
		t.Fatalf("unknown field should not be scanned as raw text, got %+v", requestEntry.Findings)
	}
}

func TestBlockRequestAnthropicErrorShape(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("blocked request must not reach upstream")
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
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "block"}},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	input := `{"model":"claude-3","messages":[{"role":"user","content":"key is TESTKEYABCDEFGHIJKLMNOP"}]}`
	resp, err := http.Post(server.URL+"/anthropic/v1/messages", "application/json", strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "contextshield_blocked") {
		t.Fatalf("expected contextshield_blocked code, got %q", body)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if tp, _ := parsed["type"].(string); tp != "error" {
		t.Fatalf("expected error type wrapper, got %+v", parsed)
	}
	errObj, ok := parsed["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected Anthropic error shape, got %+v", parsed)
	}
	if tp, _ := errObj["type"].(string); tp != "contextshield_blocked" {
		t.Fatalf("error type: expected contextshield_blocked, got %q", tp)
	}

	if strings.Contains(string(body), "TESTKEY") {
		t.Fatal("block error must never contain matched value")
	}
}

func TestMaskRequestBody(t *testing.T) {
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamBody, _ = io.ReadAll(r.Body)
		w.Write(upstreamBody)
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

	input := `{"model":"gpt-4","messages":[{"role":"user","content":"TESTKEYABCDEFGHIJKLMNOP"}],"keep":"intact"}`
	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)
	unmaskedPart := string(responseBody)

	if bytes.Contains(upstreamBody, []byte("TESTKEYABCDEFGHIJKLMNOP")) {
		t.Fatal("masked body must not contain original value")
	}
	if !strings.Contains(unmaskedPart, "keep") || !strings.Contains(unmaskedPart, "intact") {
		t.Fatal("unmatched bytes must be preserved in masked body")
	}

	if !bytes.Equal(upstreamBody, responseBody) {
		t.Fatal("response should echo masked body byte-for-byte")
	}

	ledgerLines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var requestEntry ledger.Entry
	for _, line := range ledgerLines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "request" {
			requestEntry = entry
			break
		}
	}
	if requestEntry.Verdict != ledger.VerdictMasked {
		t.Fatalf("expected masked verdict, got %q", requestEntry.Verdict)
	}
}

func TestMaskResponseBodyAndLedgerFindingsAreResponseOnly(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"content":"RESPKEYABCDEFGHIJKLMNOP"}`))
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{
		{
			ID:          "request-key",
			Class:       "secret.request_key",
			Pattern:     `\bREQKEY[0-9A-Z]{16}\b`,
			MaxMatchLen: 22,
			Keywords:    []string{"REQKEY"},
		},
		{
			ID:          "response-key",
			Class:       "secret.response_key",
			Pattern:     `\bRESPKEY[0-9A-Z]{16}\b`,
			MaxMatchLen: 23,
			Keywords:    []string{"RESPKEY"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.response_key"}, Action: "mask"}},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"REQKEYABCDEFGHIJKLMNOP"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(responseBody, []byte("RESPKEYABCDEFGHIJKLMNOP")) {
		t.Fatalf("masked response must not contain original value: %q", responseBody)
	}
	if !bytes.Contains(responseBody, []byte(`"content":"***********************"`)) {
		t.Fatalf("expected response secret to be masked in place, got %q", responseBody)
	}

	ledgerLines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	if len(ledgerLines) != 2 {
		t.Fatalf("expected request and response ledger lines, got %d: %s", len(ledgerLines), ledgerBuf.String())
	}

	var requestEntry ledger.Entry
	if err := json.Unmarshal([]byte(ledgerLines[0]), &requestEntry); err != nil {
		t.Fatal(err)
	}
	if requestEntry.Verdict != ledger.VerdictForwarded {
		t.Fatalf("expected request forwarded, got %q", requestEntry.Verdict)
	}

	var responseEntry ledger.Entry
	if err := json.Unmarshal([]byte(ledgerLines[1]), &responseEntry); err != nil {
		t.Fatal(err)
	}
	if responseEntry.Verdict != ledger.VerdictMasked {
		t.Fatalf("expected response masked verdict, got %q", responseEntry.Verdict)
	}
	for _, finding := range responseEntry.Findings {
		if finding.Class == "secret.request_key" {
			t.Fatalf("response ledger must not inherit request findings: %+v", responseEntry.Findings)
		}
	}
	if len(responseEntry.Findings) != 1 || responseEntry.Findings[0].Class != "secret.response_key" {
		t.Fatalf("expected response finding only, got %+v", responseEntry.Findings)
	}
}

func TestLogOnlyForwardsUnchanged(t *testing.T) {
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamBody, _ = io.ReadAll(r.Body)
		w.Write(upstreamBody)
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

	input := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"TESTKEYABCDEFGHIJKLMNOP"}]}`)
	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)

	if !bytes.Equal(input, responseBody) {
		t.Fatalf("log_only must forward unchanged bytes")
	}
	if !bytes.Equal(input, upstreamBody) {
		t.Fatalf("upstream must receive unchanged bytes")
	}

	ledgerLines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var requestEntry ledger.Entry
	for _, line := range ledgerLines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "request" {
			requestEntry = entry
			break
		}
	}
	if requestEntry.Verdict != ledger.VerdictForwarded {
		t.Fatalf("expected forwarded verdict, got %q", requestEntry.Verdict)
	}
	if len(requestEntry.Findings) == 0 {
		t.Fatal("expected findings in ledger")
	}
	found := false
	for _, f := range requestEntry.Findings {
		if f.Class == "secret.test_key" && f.Action == "log_only" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected log_only finding for secret.test_key, got %+v", requestEntry.Findings)
	}
}

func TestExemptionEmitsExemptedVerdict(t *testing.T) {
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamBody, _ = io.ReadAll(r.Body)
		w.Write(upstreamBody)
	}))
	defer upstream.Close()

	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "test-key",
		Class:       "secret.allowed_key",
		Pattern:     `\bALLOWEDKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 26,
		Keywords:    []string{"ALLOWEDKEY"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "block"}},
		Exemptions: []policy.Exemption{
			{Class: "secret.allowed_key", Destination: upstream.Listener.Addr().String()},
		},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	input := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"ALLOWEDKEYABCDEFGHIJKLMNOP"}]}`)
	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("exempted request should be forwarded, got status %d", resp.StatusCode)
	}
	responseBody, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(input, responseBody) {
		t.Fatalf("exempted body must forward unchanged")
	}

	ledgerLines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var requestEntry ledger.Entry
	for _, line := range ledgerLines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "request" {
			requestEntry = entry
			break
		}
	}
	if requestEntry.Verdict != ledger.VerdictExempted {
		t.Fatalf("expected exempted verdict, got %q", requestEntry.Verdict)
	}
	if len(requestEntry.Findings) == 0 {
		t.Fatal("expected findings in exempted ledger entry")
	}
}

func TestLogOnlyRecordsFindings(t *testing.T) {
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

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

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

	input := `{"model":"gpt-4","messages":[{"role":"user","content":"TESTKEYABCDEFGHIJKLMNOP"}]}`
	http.Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(input))

	ledgerLines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	var requestEntry ledger.Entry
	for _, line := range ledgerLines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Direction == "request" {
			requestEntry = entry
			break
		}
	}

	if requestEntry.Verdict != ledger.VerdictForwarded {
		t.Fatalf("expected forwarded, got %q", requestEntry.Verdict)
	}
	if len(requestEntry.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if requestEntry.Findings[0].Class != "secret.test_key" {
		t.Fatalf("expected secret.test_key, got %q", requestEntry.Findings[0].Class)
	}
	if requestEntry.Findings[0].Count < 1 {
		t.Fatalf("expected count >= 1, got %d", requestEntry.Findings[0].Count)
	}
}

func TestMaskPreservesUnmodifiedBytes(t *testing.T) {
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
	body := []byte(`{"prefix":"test","secret":"TESTKEYABCDEFGHIJKLMNOP","suffix":"keep"}`)
	findings := eng.Find(body)

	cfg := &policy.Config{
		Defaults: policy.Defaults{Action: "log_only", OnError: "closed"},
		Rules:    []policy.Rule{{Classes: []string{"secret.*"}, Action: "mask"}},
	}
	eval := policy.NewEvaluator(cfg)

	maskSpans := []engine.Finding{}
	for _, f := range findings {
		result := eval.Evaluate(f.Class, "api.test.com", f.Confidence)
		if result.Action == policy.ActionMask {
			maskSpans = append(maskSpans, f)
		}
	}

	masked := maskBody(body, maskSpans)
	if bytes.Contains(masked, []byte("TESTKEYABCDEFGHIJKLMNOP")) {
		t.Fatal("masked body must not contain original value")
	}
	if !bytes.Contains(masked, []byte(`"prefix":"test"`)) {
		t.Fatal("prefix portion must be preserved")
	}
	if !bytes.Contains(masked, []byte(`"suffix":"keep"`)) {
		t.Fatal("suffix portion must be preserved")
	}
	if !bytes.HasPrefix(masked, []byte(`{"prefix":"test","secret":"`)) {
		t.Fatalf("body before mask must be preserved intact")
	}
}

func TestLedgerNeverStoresValues(t *testing.T) {
	var ledgerBuf bytes.Buffer
	lw := ledger.NewWriter(&ledgerBuf)

	eng, err := engine.NewMatcher([]engine.Rule{{
		ID:          "pan-test",
		Class:       "regulated.credit_card",
		Pattern:     `\b(?:\d[ -]?){13,19}\b`,
		MaxMatchLen: 38,
		Keywords:    []string{"4111"},
		Validators:  []string{"luhn", "iin_prefix", "length_per_network"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"ok"}`))
	}))
	defer upstream.Close()

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

	http.Post(server.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"card":"4111 1111 1111 1111"}`))

	ledgerStr := ledgerBuf.String()
	if strings.Contains(ledgerStr, "4111") || strings.Contains(ledgerStr, "1111") {
		t.Fatal("ledger must never contain values: " + ledgerStr)
	}
}

func TestNoEngineNoScanning(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
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
		strings.NewReader(`{"key":"should not be scanned"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestOnErrorClosedFailsWithLedgerError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	upstreamURL := upstream.URL
	upstream.Close()

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
		Upstreams: map[string]string{"test": upstreamURL},
		Defaults:  policy.Defaults{Action: "log_only", OnError: "closed"},
	}

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"test":"data"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}

	ledgerLines := strings.Split(strings.TrimSpace(ledgerBuf.String()), "\n")
	hasError := false
	for _, line := range ledgerLines {
		var entry ledger.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Verdict == ledger.VerdictError {
			hasError = true
			break
		}
	}
	if !hasError {
		t.Fatal("expected an error verdict in ledger entries")
	}
}
