package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/theanh/contextshield/engine"
	"github.com/theanh/contextshield/ledger"
	"github.com/theanh/contextshield/policy"
)

// BenchmarkRequestPathLatency measures the latency ContextShield adds to a
// NON-streaming request/response round trip — the companion to
// BenchmarkStreamingTTFT so the Day-7 README can publish measured p50/p99 for
// BOTH the request path and streaming (the ship criteria require both).
//
// Method: each iteration issues the SAME request twice — once straight to an
// in-process upstream (the baseline) and once through the gateway — and records
// both latencies. The gateway path adds a second localhost hop plus a full
// request-body scan (all five production rules) and, in the with-secret
// variant, a mask rewrite. Reporting the two populations side by side makes the
// added overhead (reqpath_p50 − direct_p50) an honest, isolated number rather
// than one polluted by absolute socket cost.
//
// Reported metrics (milliseconds, via b.ReportMetric):
//   - reqpath_p50_ms / reqpath_p99_ms : absolute round trip through the gateway
//   - direct_p50_ms  / direct_p99_ms  : baseline round trip to the upstream
//   - added_p50_ms   / added_p99_ms   : gateway overhead (reqpath − direct)
//
// Variants mirror the streaming benchmark:
//   - clean:       no findings; byte-identical passthrough (the common case)
//   - with-secret: request body carries an AWS key; exercises scan + mask
func BenchmarkRequestPathLatency(b *testing.B) {
	benchRequestPath(b, false)
}

func BenchmarkRequestPathLatencyWithSecret(b *testing.B) {
	benchRequestPath(b, true)
}

func benchRequestPath(b *testing.B, withSecret bool) {
	eng, err := engine.NewMatcher(loadProductionRules(b))
	if err != nil {
		b.Fatal(err)
	}

	// Realistic non-streaming completion response, returned immediately so the
	// measurement captures gateway overhead rather than upstream think-time.
	const respBody = `{"id":"chatcmpl-bench","object":"chat.completion",` +
		`"choices":[{"index":0,"message":{"role":"assistant",` +
		`"content":"Here is a concise summary of the requested planning notes."},` +
		`"finish_reason":"stop"}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(respBody))
	}))
	defer upstream.Close()

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "mask", OnError: "closed"},
		Rules:     []policy.Rule{{Classes: []string{"secret.*"}, Action: "mask"}},
	}
	ledgerBuf := &bytes.Buffer{}
	lw := ledger.NewWriter(ledgerBuf)

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		b.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	// A representative OpenAI chat body. The clean prompt carries no detectable
	// data; the secret prompt embeds an AWS access key that the real rule masks.
	cleanContent := "Summarize the quarterly planning notes and list the top three " +
		"action items the platform team should review before the next sprint kickoff."
	secretContent := "Rotate the deploy role credential AKIAIOSFODNN7EXAMPLE and remove " +
		"it from the shared configuration before the next sprint kickoff."
	content := cleanContent
	if withSecret {
		content = secretContent
	}
	quotedContent, err := json.Marshal(content)
	if err != nil {
		b.Fatal(err)
	}
	reqBody := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":` +
		string(quotedContent) + `}]}`)

	directURL := upstream.URL + "/v1/chat/completions"
	gatewayURL := server.URL + "/v1/chat/completions"

	const warmup = 10
	for i := 0; i < warmup; i++ {
		doRequestPath(b, directURL, reqBody)
		doRequestPath(b, gatewayURL, reqBody)
	}

	directLat := make([]int64, 0, b.N)
	gatewayLat := make([]int64, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t0 := time.Now()
		doRequestPath(b, directURL, reqBody)
		t1 := time.Now()
		doRequestPath(b, gatewayURL, reqBody)
		t2 := time.Now()
		directLat = append(directLat, int64(t1.Sub(t0)))
		gatewayLat = append(gatewayLat, int64(t2.Sub(t1)))
	}
	b.StopTimer()

	gwP50, gwP99 := percentiles(gatewayLat)
	dP50, dP99 := percentiles(directLat)
	b.ReportMetric(gwP50, "reqpath_p50_ms")
	b.ReportMetric(gwP99, "reqpath_p99_ms")
	b.ReportMetric(dP50, "direct_p50_ms")
	b.ReportMetric(dP99, "direct_p99_ms")
	b.ReportMetric(gwP50-dP50, "added_p50_ms")
	b.ReportMetric(gwP99-dP99, "added_p99_ms")
}

// doRequestPath issues one non-streaming POST and fully drains the response so
// the keep-alive connection is reused across iterations (otherwise every
// iteration pays a fresh TCP+handshake cost that would swamp the signal).
func doRequestPath(b *testing.B, url string, body []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		resp.Body.Close()
		b.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b.Fatalf("unexpected status %d", resp.StatusCode)
	}
}

// loadProductionRules loads the five shipped detection rules from disk so the
// benchmark measures the real scan cost, matching engine_test's loadFixtureRules.
func loadProductionRules(b *testing.B) []engine.Rule {
	b.Helper()
	paths := []string{
		"../rules/secrets/aws-access-key-id.yaml",
		"../rules/secrets/generic-high-entropy.yaml",
		"../rules/regulated/credit-card-pan.yaml",
		"../rules/regulated/iban.yaml",
		"../rules/structural/ssn.yaml",
	}
	rules := make([]engine.Rule, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			b.Fatal(err)
		}
		rule, err := engine.ParseRuleYAML(data)
		if err != nil {
			b.Fatal(err)
		}
		rules = append(rules, rule)
	}
	return rules
}
