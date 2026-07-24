package gate

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/theanh/contextshield/engine"
	"github.com/theanh/contextshield/ledger"
	"github.com/theanh/contextshield/policy"
)

// BenchmarkStreamingTTFT measures the latency the gateway adds between
// "upstream sends its first SSE byte" and "client reads its first SSE byte".
// This is the Day-4 ship gate (D-16): measured p50/p99 TTFT overhead must
// be ≤ 50 ms at p50, published either way.
//
// The benchmark runs an in-process upstream that emits tokens at a typical
// streaming rate (~300 B/s, ~75 tok/s) and measures the added latency per
// request across N requests. p50/p99 are reported via b.ReportMetric and
// also returned for the eval-reporting gate (a separate TestStreamingTTFT
// asserts the p50 target on a fixed population).
//
// Variants:
//   - clean:        no findings (the common case; D-16 promises ~0 ms here)
//   - with-secret:  payload contains a split-able TESTKEY secret; exercises
//                   pendingLiteral + mask path
//
// The benchmark writes no ledger to disk (in-memory buffer) so FS sync
// doesn't dominate the measurement.
func BenchmarkStreamingTTFT(b *testing.B) {
	benchStreamingTTFT(b, false)
}

func BenchmarkStreamingTTFTWithSecret(b *testing.B) {
	benchStreamingTTFT(b, true)
}

func benchStreamingTTFT(b *testing.B, withSecret bool) {
	rules := []engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}}
	eng, err := engine.NewMatcher(rules)
	if err != nil {
		b.Fatal(err)
	}

	// Representative streaming payload: prose with no anchor (clean path)
	// or prose embedding a TESTKEY secret split across two events (mask path).
	// Each "token" event is ~6 bytes (4-byte word + JSON envelope overhead),
	// emitted at ~75 tok/s = ~450 B/s.
	proseEvents := []string{
		"The ", "model ", "completes ", "a ", "sentence ", "one ", "token ", "at ", "a ", "time ", "and ", "we ", "measure ", "the ", "latency ",
	}
	secretEvents := []string{
		"The ", "key ", "is ", "TESTKEYAB", "CDEFGHIJKLMNOP", " done ",
	}
	events := proseEvents
	if withSecret {
		events = secretEvents
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		// Simulate ~75 tok/s by spacing event writes ~13ms apart.
		ticker := time.NewTicker(13 * time.Millisecond)
		defer ticker.Stop()
		for _, tok := range events {
			w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"" + tok + "\"}}]}\n\n"))
			flusher.Flush()
			<-ticker.C
		}
		w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "mask", OnError: "closed"},
	}
	ledgerBuf := &bytes.Buffer{}
	lw := ledger.NewWriter(ledgerBuf)

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		b.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	const warmup = 5
	for i := 0; i < warmup; i++ {
		doStreamingRequest(b, server.URL)
	}

	// Latencies in nanoseconds.
	var latencies []int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		firstByteAt := doStreamingRequest(b, server.URL)
		latencies = append(latencies, int64(firstByteAt.Sub(start)))
	}
	b.StopTimer()

	p50, p99 := percentiles(latencies)
	// Report in milliseconds (b.ReportMetric treats the float as the unit
	// implied by the metric name; we name them "ttft_p50_ms" etc.).
	b.ReportMetric(p50, "ttft_p50_ms")
	b.ReportMetric(p99, "ttft_p99_ms")
}

// doStreamingRequest issues a streaming request and returns the time at
// which the first decoded byte was received from the gateway. It drains the
// body so the gateway's reader doesn't emit a context-canceled log line on
// every iteration (which would flood the benchmark output).
func doStreamingRequest(b *testing.B, serverURL string) time.Time {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/v1/chat/completions",
		bytes.NewReader([]byte(`{"model":"gpt-4","stream":true}`)))
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 64)
	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		b.Fatal(err)
	}
	if n == 0 {
		b.Fatal("no bytes received from gateway")
	}
	firstByteAt := time.Now()
	// Drain the rest so the gateway's stream reader sees EOF, not cancel.
	io.Copy(io.Discard, resp.Body)
	return firstByteAt
}

func percentiles(samples []int64) (float64, float64) {
	if len(samples) == 0 {
		return 0, 0
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p50 := float64(samples[int(float64(len(samples))*0.5)]) / float64(time.Millisecond)
	p99 := float64(samples[int(float64(len(samples))*0.99)]) / float64(time.Millisecond)
	return p50, p99
}

// TestStreamingTTFTUnderTarget asserts the Day-4 acceptance gate: the
// measured p50 TTFT overhead the gateway adds to a clean stream is
// ≤ 50 ms. Per D-16/fallback, if this fails we must either improve the
// automaton-state hold-back or formally switch to the documented fallback
// (small fixed window + anchored rules). Either way the number is published.
//
// This test runs a small population (20 requests) and asserts the p50 is
// under the target. It is not a microbenchmark — it includes real socket
// I/O and therefore has measurement noise; the assertion is deliberately
// generous (50 ms target, not nanosecond-precision).
func TestStreamingTTFTUnderTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("TTFT measurement requires real server; skipped in -short mode")
	}
	rules := []engine.Rule{{
		ID:          "test-key",
		Class:       "secret.test_key",
		Pattern:     `\bTESTKEY[0-9A-Z]{16}\b`,
		MaxMatchLen: 23,
		Keywords:    []string{"TESTKEY"},
	}}
	eng, err := engine.NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}

	// Clean prose — exercises the D-16 promise that p50 hold is ~0.
	events := []string{"Hello ", "world ", "this ", "is ", "a ", "streaming ", "test ", "of ", "the ", "gateway."}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		// Emit immediately (no inter-token delay) so the measurement
		// captures gateway overhead, not upstream pacing.
		for _, tok := range events {
			w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"" + tok + "\"}}]}\n\n"))
			flusher.Flush()
		}
		w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	cfg := &policy.Config{
		Listen:    ":0",
		Upstreams: map[string]string{"test": upstream.URL},
		Defaults:  policy.Defaults{Action: "mask", OnError: "closed"},
	}
	ledgerBuf := &bytes.Buffer{}
	lw := ledger.NewWriter(ledgerBuf)

	gw, err := NewGateway(cfg, lw, eng)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gw)
	defer server.Close()

	const n = 20
	const warmup = 3
	for i := 0; i < warmup; i++ {
		readFirstByte(t, server.URL)
	}
	var samples []int64
	for i := 0; i < n; i++ {
		start := time.Now()
		firstAt := readFirstByte(t, server.URL)
		samples = append(samples, int64(firstAt.Sub(start)))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p50 := time.Duration(samples[n/2])
	p99 := time.Duration(samples[(n*99)/100])
	t.Logf("TTFT p50=%v p99=%v (n=%d)", p50, p99, n)

	// The Day-4 target: ≤ 50 ms p50 added TTFT. This is end-to-end (gateway
	// socket + reader) so includes some baseline socket cost; the D-16
	// promise is that *hold-back* adds ~0 at p50, so total p50 must stay
	// well under 50 ms on a clean (no-finding) stream.
	const target = 50 * time.Millisecond
	if p50 > target {
		t.Fatalf("p50 TTFT %v exceeds 50 ms target — D-16 fallback decision required (see decisions.md)", p50)
	}
}

func readFirstByte(t *testing.T, serverURL string) time.Time {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/v1/chat/completions",
		bytes.NewReader([]byte(`{"model":"gpt-4","stream":true}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 1)
	if _, err := resp.Body.Read(buf); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return time.Now()
}