package gate

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/theanh/contextshield/adapter"
	"github.com/theanh/contextshield/engine"
	"github.com/theanh/contextshield/ledger"
	"github.com/theanh/contextshield/policy"
)

const ledgerSchemaVersion = "0.1.0"

type Gateway struct {
	config    *policy.Config
	evaluator *policy.Evaluator
	engine    *engine.Matcher
	ledger    *ledger.Writer
	upstreams map[string]*url.URL
	transport http.RoundTripper
	server    *http.Server
}

func NewGateway(cfg *policy.Config, lw *ledger.Writer, eng *engine.Matcher) (*Gateway, error) {
	upstreams := make(map[string]*url.URL, len(cfg.Upstreams))
	for name, base := range cfg.Upstreams {
		u, err := url.Parse(base)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream %q: %w", name, err)
		}
		upstreams[name] = u
	}

	return &Gateway{
		config:    cfg,
		evaluator: policy.NewEvaluator(cfg),
		engine:    eng,
		ledger:    lw,
		upstreams: upstreams,
		transport: noCompressionTransport(),
	}, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := newReqID()
	start := time.Now()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		g.emitError(reqID, "request", r.Host, "", "", "read_body", w)
		return
	}
	r.Body.Close()

	bodySHA := ledger.BodySHA256(body)
	model := extractModel(body)

	upstream, _, path, err := g.selectUpstream(r, body)
	if err != nil {
		g.emitError(reqID, "request", r.Host, model, bodySHA, err.Error(), w)
		return
	}

	destination := upstream.Host

	forwardBody := body
	verdict := ledger.VerdictForwarded
	ledgerFindings := []ledger.Finding{}
	unscannedFields := []string{}

	if g.engine != nil {
		engineFindings, fields, err := g.scanRequestBody(path, body)
		if err != nil {
			g.emitError(reqID, "request", destination, model, bodySHA, "scan_request: "+err.Error(), w)
			return
		}
		unscannedFields = fields
		verdict, ledgerFindings, forwardBody = g.applyActions(reqID, "request", body, engineFindings, destination, path, w)
		if verdict == ledger.VerdictBlocked {
			g.emitLedgerWithUnscanned(reqID, "request", destination, model, bodySHA, start, ledgerFindings, verdict, unscannedFields)
			return
		}
	}

	targetURL := upstream.ResolveReference(&url.URL{Path: path, RawQuery: r.URL.RawQuery})

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), bytes.NewReader(forwardBody))
	if err != nil {
		g.emitError(reqID, "request", upstream.Host, model, bodySHA, "create_proxy", w)
		return
	}

	copyHeaders(proxyReq.Header, r.Header)
	removeHopByHopHeaders(proxyReq.Header)
	proxyReq.Header.Set("X-ContextShield-Request-ID", reqID)

	resp, err := g.transport.RoundTrip(proxyReq)
	if err != nil {
		g.emitError(reqID, "request", upstream.Host, model, bodySHA, "upstream: "+err.Error(), w)
		return
	}
	defer resp.Body.Close()

	g.emitLedgerWithUnscanned(reqID, "request", destination, model, bodySHA, start, ledgerFindings, verdict, unscannedFields)

	if isStreamingResponse(resp) {
		g.handleStreamingResponse(w, resp, reqID, destination, model, path)
		return
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		g.emitError(reqID, "response", upstream.Host, "", "", "read_response", w)
		return
	}

	respSHA := ledger.BodySHA256(respBody)

	respVerdict := ledger.VerdictForwarded
	respLedgerFindings := []ledger.Finding{}
	if g.engine != nil {
		respFindings := g.engine.Find(respBody)
		if len(respFindings) > 0 {
			var updatedRespBody []byte
			respVerdict, respLedgerFindings, updatedRespBody = g.applyActions(reqID, "response", respBody, respFindings, destination, path, w)
			if respVerdict == ledger.VerdictBlocked {
				g.emitLedger(reqID, "response", destination, model, respSHA, time.Now(), respLedgerFindings, respVerdict)
				return
			}
			respBody = updatedRespBody
		}
	}

	g.emitLedger(reqID, "response", destination, model, respSHA, time.Now(), respLedgerFindings, respVerdict)

	respHeaders := resp.Header.Clone()
	removeHopByHopHeaders(respHeaders)
	copyHeaders(w.Header(), respHeaders)
	w.WriteHeader(resp.StatusCode)

	if _, err := w.Write(respBody); err != nil {
		log.Printf("response write: %v", err)
	}
}

func (g *Gateway) applyActions(reqID, direction string, body []byte, findings []engine.Finding, destination, path string, w http.ResponseWriter) (ledger.Verdict, []ledger.Finding, []byte) {
	if len(findings) == 0 {
		return ledger.VerdictForwarded, nil, body
	}

	classActions := map[string]map[string]int{}
	var blockDetail *policy.BlockDetail
	maskSpans := []engine.Finding{}
	anyExempted := false
	allExempted := true

	for _, f := range findings {
		result := g.evaluator.Evaluate(f.Class, destination, f.Confidence)
		action := result.Action

		if result.Exempted {
			anyExempted = true
		} else {
			allExempted = false
		}

		if _, ok := classActions[f.Class]; !ok {
			classActions[f.Class] = map[string]int{}
		}
		classActions[f.Class][string(action)]++

		switch action {
		case policy.ActionBlock:
			if blockDetail == nil {
				blockDetail = &policy.BlockDetail{
					Class:     f.Class,
					RuleID:    f.RuleID,
					RequestID: reqID,
				}
			}
		case policy.ActionMask:
			maskSpans = append(maskSpans, f)
		}
	}

	verdict := ledger.VerdictForwarded
	if blockDetail != nil {
		status, blockBody := policy.BlockErrorForPath(path, direction, *blockDetail)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(blockBody)
		verdict = ledger.VerdictBlocked
	} else if len(maskSpans) > 0 {
		body = maskBody(body, maskSpans)
		verdict = ledger.VerdictMasked
	} else if allExempted && anyExempted {
		verdict = ledger.VerdictExempted
	}

	ledgerFindings := []ledger.Finding{}
	for class, actions := range classActions {
		for action, count := range actions {
			ledgerFindings = append(ledgerFindings, ledger.Finding{
				Class:  class,
				Count:  count,
				Action: action,
			})
		}
	}

	return verdict, ledgerFindings, body
}

func (g *Gateway) scanRequestBody(path string, body []byte) ([]engine.Finding, []string, error) {
	result, err := adapter.Extract(path, body)
	if err != nil {
		if errors.Is(err, adapter.ErrUnsupportedPath) {
			return g.engine.Find(body), result.UnscannedFields, nil
		}
		return nil, nil, err
	}

	findings := []engine.Finding{}
	seen := map[string]struct{}{}
	for _, unit := range result.Units {
		unitFindings := g.engine.Find([]byte(unit.Text))
		for _, finding := range unitFindings {
			rawStart, rawEnd, ok := unit.RawSpan(finding.Start, finding.End)
			if !ok {
				rawStart = unit.RawContentStart
				rawEnd = unit.RawContentEnd
			}
			if rawStart < 0 || rawEnd <= rawStart || rawEnd > len(body) {
				continue
			}
			key := fmt.Sprintf("%s:%d:%d", finding.RuleID, rawStart, rawEnd)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, engine.Finding{
				RuleID:     finding.RuleID,
				Class:      finding.Class,
				Start:      rawStart,
				End:        rawEnd,
				Confidence: finding.Confidence,
			})
		}
	}
	return findings, result.UnscannedFields, nil
}

func maskBody(body []byte, findings []engine.Finding) []byte {
	type span struct{ start, end int }
	spans := make([]span, 0, len(findings))
	for _, f := range findings {
		spans = append(spans, span{f.Start, f.End})
	}

	sort.Slice(spans, func(i, j int) bool {
		return spans[i].start < spans[j].start
	})

	merged := []span{spans[0]}
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.start <= last.end {
			if s.end > last.end {
				last.end = s.end
			}
		} else {
			merged = append(merged, s)
		}
	}

	var buf bytes.Buffer
	pos := 0
	for _, s := range merged {
		buf.Write(body[pos:s.start])
		buf.Write(bytes.Repeat([]byte{'*'}, s.end-s.start))
		pos = s.end
	}
	buf.Write(body[pos:])
	return buf.Bytes()
}

func (g *Gateway) emitLedger(reqID, direction, dest, model, bodySHA string, ts time.Time, findings []ledger.Finding, verdict ledger.Verdict) {
	g.emitLedgerWithUnscanned(reqID, direction, dest, model, bodySHA, ts, findings, verdict, nil)
}

func (g *Gateway) emitLedgerWithUnscanned(reqID, direction, dest, model, bodySHA string, ts time.Time, findings []ledger.Finding, verdict ledger.Verdict, unscannedFields []string) {
	if findings == nil {
		findings = []ledger.Finding{}
	}
	if err := g.ledger.Append(ledger.Entry{
		SchemaVersion:   ledgerSchemaVersion,
		Timestamp:       ts.UTC().Format(time.RFC3339Nano),
		RequestID:       reqID,
		Direction:       direction,
		Dest:            dest,
		Model:           model,
		Findings:        findings,
		UnscannedFields: unscannedFields,
		Verdict:         verdict,
		BodySHA:         bodySHA,
	}); err != nil {
		log.Printf("ledger: %v", err)
	}
}

func (g *Gateway) selectUpstream(r *http.Request, body []byte) (upstream *url.URL, name, path string, err error) {
	if len(g.upstreams) == 1 {
		for n, u := range g.upstreams {
			first, rest := splitPath(r.URL.Path)
			if first == n {
				return u, n, rest, nil
			}
			return u, n, r.URL.Path, nil
		}
	}

	first, rest := splitPath(r.URL.Path)
	if u, ok := g.upstreams[first]; ok {
		return u, first, rest, nil
	}

	if model := extractModel(body); model != "" {
		name := modelToUpstream(model)
		if u, ok := g.upstreams[name]; ok {
			return u, name, r.URL.Path, nil
		}
	}

	return nil, "", "", fmt.Errorf("unknown_upstream: no route for path=%s", r.URL.Path)
}

func (g *Gateway) emitError(reqID, direction, dest, model, bodySHA, detail string, w http.ResponseWriter) {
	g.emitLedger(reqID, direction, dest, model, bodySHA, time.Now(), nil, ledger.VerdictError)
	http.Error(w, fmt.Sprintf("contextshield: %s", detail), http.StatusBadGateway)
}

func splitPath(path string) (first, rest string) {
	path = strings.TrimPrefix(path, "/")
	idx := strings.IndexByte(path, '/')
	if idx == -1 {
		return path, "/"
	}
	return path[:idx], path[idx:]
}

func extractModel(body []byte) string {
	var v struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return ""
	}
	return v.Model
}

func modelToUpstream(model string) string {
	model = strings.ToLower(model)
	switch {
	case strings.Contains(model, "claude"):
		return "anthropic"
	case strings.Contains(model, "gpt"), strings.Contains(model, "o1"), strings.Contains(model, "o3"):
		return "openai"
	default:
		return model
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

var hopByHop = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

func isStreamingResponse(resp *http.Response) bool {
	for _, value := range resp.Header.Values("Content-Type") {
		mediaType := strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
		if mediaType == "text/event-stream" {
			return true
		}
	}
	return false
}

func noCompressionTransport() http.RoundTripper {
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		tr := base.Clone()
		tr.DisableCompression = true
		return tr
	}
	return http.DefaultTransport
}

func (g *Gateway) HTTPServer() *http.Server {
	return &http.Server{
		Addr:    g.config.Listen,
		Handler: g,
	}
}

func newReqID() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<48))
	if err != nil {
		return fmt.Sprintf("r_%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("r_%012x", n)
}
