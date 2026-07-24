package gate

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/theanh/contextshield/engine"
	"github.com/theanh/contextshield/ledger"
	"github.com/theanh/contextshield/policy"
)

type streamScanner struct {
	eng       *engine.Matcher
	evaluator *policy.Evaluator
	dest      string
	path      string
	reqID     string

	// streamScan is the engine's incremental automaton-state hold-back
	// (per D-16). It tracks AC state across chunks so we hold only viable
	// partial-match bytes (0–20 on typical prose), not max(max_match_len)
	// globally — that fixed-window approach is what D-16 explicitly rejected.
	streamScan *engine.StreamScan

	// decoded is the running decoded text fed to the engine so far. It is
	// appended to per event (never re-materialized), so the offsets recorded
	// in pending events and mask spans stay stable across the stream.
	decoded []byte
	// feededDecodedLen is the number of bytes from ss.decoded that have
	// already been fed to ss.streamScan. Each scanAndFlush call feeds only
	// the newly appended chunk so the engine advances its AC state across
	// Feed calls — never re-feeds the whole buffer (which would re-trigger
	// AC state from the root each time).
	feededDecodedLen int
	pending          []pendingEvent

	// allFindings accumulates findings across Feed calls so the ledger
	// summarizer never re-runs the full-buffer match (which was both O(n)
	// per chunk and the wrong shape — StreamScan deduped by candidateKey
	// across calls; Find over the whole buffer would re-emit duplicates).
	allFindings []engine.Finding

	maskSpans   []engine.Finding
	blocked     bool
	blockDetail *policy.BlockDetail

	unscannedFields []string
	seenUnscanned   map[string]struct{}
}

type pendingEvent struct {
	raw          []byte
	decodedStart int
	decodedEnd   int
}

type streamTextResult struct {
	text      string
	unscanned []string
}

func newStreamScanner(eng *engine.Matcher, eval *policy.Evaluator, dest, path, reqID string) *streamScanner {
	ss := &streamScanner{
		eng:           eng,
		evaluator:     eval,
		dest:          dest,
		path:          path,
		reqID:         reqID,
		seenUnscanned: map[string]struct{}{},
	}
	if eng != nil {
		ss.streamScan = eng.NewStreamScan()
	}
	return ss
}

func extractStreamDelta(path, eventType string, data []byte) streamTextResult {
	switch {
	case strings.HasSuffix(path, "/chat/completions"):
		return extractOpenAIChatStreamDelta(data)
	case strings.HasSuffix(path, "/messages"):
		return extractAnthropicStreamDelta(eventType, data)
	case strings.HasSuffix(path, "/responses"):
		return extractOpenAIResponsesStreamDelta(eventType, data)
	}
	return streamTextResult{}
}

func extractOpenAIChatStreamDelta(data []byte) streamTextResult {
	var root struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
		Usage interface{} `json:"usage"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return streamTextResult{}
	}
	var text strings.Builder
	for _, c := range root.Choices {
		text.WriteString(c.Delta.Content)
	}

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err == nil {
		unscanned := knownFieldsDiff(rawMap, openAIStreamChatKnown)
		return streamTextResult{text: text.String(), unscanned: unscanned}
	}
	return streamTextResult{text: text.String()}
}

func extractAnthropicStreamDelta(eventType string, data []byte) streamTextResult {
	if eventType != "content_block_delta" {
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(data, &rawMap); err == nil {
			unscanned := knownFieldsDiff(rawMap, anthropicStreamKnown)
			return streamTextResult{unscanned: unscanned}
		}
		return streamTextResult{}
	}
	var root struct {
		Delta struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"delta"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return streamTextResult{}
	}
	if root.Delta.Type == "text_delta" {
		return streamTextResult{text: root.Delta.Text}
	}
	return streamTextResult{}
}

func extractOpenAIResponsesStreamDelta(eventType string, data []byte) streamTextResult {
	if eventType != "response.output_text.delta" {
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(data, &rawMap); err == nil {
			unscanned := knownFieldsDiff(rawMap, openAIStreamResponsesKnown)
			return streamTextResult{unscanned: unscanned}
		}
		return streamTextResult{}
	}
	var root struct {
		Delta string `json:"delta"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return streamTextResult{}
	}
	return streamTextResult{text: root.Delta}
}

var openAIStreamChatKnown = map[string]struct{}{
	"id": {}, "object": {}, "created": {}, "model": {},
	"choices": {}, "usage": {}, "system_fingerprint": {},
}

var anthropicStreamKnown = map[string]struct{}{
	"type": {}, "index": {}, "delta": {}, "message": {},
	"content_block": {}, "stop_reason": {}, "stop_sequence": {},
	"usage": {}, "id": {}, "model": {}, "role": {},
}

var openAIStreamResponsesKnown = map[string]struct{}{
	"type": {}, "delta": {}, "item_id": {}, "output_index": {},
	"part_index": {}, "id": {}, "object": {}, "created": {},
	"model": {}, "status": {}, "usage": {},
}

func knownFieldsDiff(raw map[string]json.RawMessage, known map[string]struct{}) []string {
	var f []string
	for k := range raw {
		if _, ok := known[k]; !ok {
			f = append(f, "$."+k)
		}
	}
	sort.Strings(f)
	return f
}

func (ss *streamScanner) addEvent(raw []byte, result streamTextResult) {
	startOff := len(ss.decoded)
	ss.decoded = append(ss.decoded, result.text...)
	ss.pending = append(ss.pending, pendingEvent{
		raw:          append([]byte{}, raw...),
		decodedStart: startOff,
		decodedEnd:   len(ss.decoded),
	})
	for _, f := range result.unscanned {
		if _, ok := ss.seenUnscanned[f]; !ok {
			ss.seenUnscanned[f] = struct{}{}
			ss.unscannedFields = append(ss.unscannedFields, f)
		}
	}
}

// ingest records findings from a Feed or Finalize call: it accumulates them
// for the ledger summary, latches a block verdict the moment any finding maps
// to a block action, and otherwise folds in mask spans. Once blocked it stops
// folding mask spans — the stream is withheld, not rewritten. Both the
// per-chunk path (scanAndFlush) and the end-of-stream drain (finalize) route
// through here, so neither can silently skip block detection.
func (ss *streamScanner) ingest(findings []engine.Finding) {
	ss.allFindings = append(ss.allFindings, findings...)
	if ss.blocked {
		return
	}
	if detail := ss.findBlock(findings); detail != nil {
		ss.blocked = true
		ss.blockDetail = detail
		return
	}
	ss.maskSpans = appendMaskSpans(ss.maskSpans, ss.collectMaskSpans(findings))
}

func (ss *streamScanner) scanAndFlush(w io.Writer) {
	if ss.blocked {
		return
	}
	if ss.eng == nil || len(ss.decoded) == 0 {
		ss.flushAllPending(w)
		return
	}

	// Feed just the newly-appended bytes (since the last Feed) into the
	// engine's streaming scan. The engine advances its AC state across
	// Feed calls and returns findings completed in this chunk + the live
	// hold-back length (current viable partial-match, not max(max_match_len)).
	chunkStart := ss.feededDecodedLen
	chunkEnd := len(ss.decoded)
	chunk := ss.decoded[chunkStart:chunkEnd]
	findings, hold := ss.streamScan.Feed(chunk, ss.decoded)
	ss.feededDecodedLen = chunkEnd

	ss.ingest(findings)
	if ss.blocked {
		return
	}

	// safeEnd is the position in the decoded buffer up to which we can flush
	// — everything strictly after it is held back pending more bytes for
	// the automaton to decide. hold=0 at root state (typical prose) means
	// we flush everything.
	safeEnd := len(ss.decoded) - hold
	if safeEnd < 0 {
		safeEnd = 0
	}

	events := ss.popSafeEvents(safeEnd)
	ss.flushMasked(w, events)
}

// appendMaskSpans merges new mask spans into the existing list, deduping by
// (start, end). Findings persist across Feed calls — the gateway may mask
// spans from a chunk that was held back until a later chunk confirms it.
func appendMaskSpans(existing, new []engine.Finding) []engine.Finding {
	seen := map[[2]int]struct{}{}
	for _, s := range existing {
		seen[[2]int{s.Start, s.End}] = struct{}{}
	}
	for _, s := range new {
		key := [2]int{s.Start, s.End}
		if _, ok := seen[key]; !ok {
			existing = append(existing, s)
			seen[key] = struct{}{}
		}
	}
	return existing
}

func (ss *streamScanner) findBlock(findings []engine.Finding) *policy.BlockDetail {
	for _, f := range findings {
		result := ss.evaluator.Evaluate(f.Class, ss.dest, f.Confidence)
		if !result.Exempted && result.Action == policy.ActionBlock {
			return &policy.BlockDetail{
				Class:     f.Class,
				RuleID:    f.RuleID,
				RequestID: ss.reqID,
			}
		}
	}
	return nil
}

func (ss *streamScanner) collectMaskSpans(findings []engine.Finding) []engine.Finding {
	var spans []engine.Finding
	for _, f := range findings {
		result := ss.evaluator.Evaluate(f.Class, ss.dest, f.Confidence)
		if !result.Exempted && result.Action == policy.ActionMask {
			spans = append(spans, f)
		}
	}
	return spans
}

func (ss *streamScanner) popSafeEvents(safeEnd int) []pendingEvent {
	idx := 0
	for i, evt := range ss.pending {
		if evt.decodedEnd <= safeEnd {
			idx = i + 1
		} else {
			break
		}
	}
	if idx == 0 {
		return nil
	}
	events := ss.pending[:idx]
	ss.pending = ss.pending[idx:]
	return events
}

func (ss *streamScanner) flushAllPending(w io.Writer) {
	for _, evt := range ss.pending {
		w.Write(evt.raw)
	}
	ss.pending = nil
}

func (ss *streamScanner) flushMasked(w io.Writer, events []pendingEvent) {
	for _, evt := range events {
		masked := applyMaskToEvent(evt, ss.maskSpans, ss.path)
		w.Write(masked)
	}
}

// applyMaskToEvent rewrites the carrier fields of an SSE event with their
// spans masked. Per-provider dispatch (D-21 / per the architecture's "Re-
// serialize only on mutation" rule): the previously-used recursive JSON
// walk that did strings.ReplaceAll(field, oldDecoded, masked) had a false-
// positive bug for short deltas — a one-token carrier like "a" would also
// mask unrelated string fields (model names, ids) whose value happened to
// contain that token. Targeted per-provider masking only ever touches the
// carrier field (choices[].delta.content / delta.text / delta) at known
// paths and applies local offsets to it.
//
// Multi-carrier-variation streams (e.g., an OpenAI chat chunk with multiple
// choices each contributing content) currently fall back to "return raw,
// unmasked" — flagged via unscanned_fields on the carrier at extraction time
// rather than silently mis-masking. The common streaming shape across all
// three providers is exactly one content delta per event.
//
// The data payload is reconstructed exactly as parseSSEToken builds it — a
// multi-line `data:` value is joined with '\n' — so masking operates on the
// same JSON the scanner extracted. On a match the whole payload is re-emitted
// as a single masked `data:` line (re-serialization is permitted here since we
// are mutating the event); continuation `data:` lines are dropped.
func applyMaskToEvent(evt pendingEvent, maskSpans []engine.Finding, path string) []byte {
	var local []engine.Finding
	for _, s := range maskSpans {
		overlapStart := max(s.Start, evt.decodedStart)
		overlapEnd := min(s.End, evt.decodedEnd)
		if overlapStart < overlapEnd {
			local = append(local, engine.Finding{
				Start: overlapStart - evt.decodedStart,
				End:   overlapEnd - evt.decodedStart,
			})
		}
	}
	if len(local) == 0 {
		return evt.raw
	}

	lines := bytes.Split(evt.raw, []byte("\n"))
	var payload []byte
	firstDataIdx := -1
	for i, raw := range lines {
		line := bytes.TrimSpace(raw)
		var content []byte
		switch {
		case bytes.HasPrefix(line, []byte("data: ")):
			content = bytes.TrimSpace(line[6:])
		case bytes.HasPrefix(line, []byte("data:")):
			content = bytes.TrimSpace(line[5:])
		default:
			continue
		}
		if firstDataIdx < 0 {
			firstDataIdx = i
		} else {
			payload = append(payload, '\n')
			lines[i] = nil // continuation data line; dropped on rebuild
		}
		payload = append(payload, content...)
	}
	if firstDataIdx < 0 {
		return evt.raw
	}

	maskedJSON, ok := maskProviderData(path, payload, local)
	if !ok {
		return evt.raw
	}

	lines[firstDataIdx] = append([]byte("data: "), maskedJSON...)
	rebuilt := make([][]byte, 0, len(lines))
	for _, l := range lines {
		if l == nil {
			continue
		}
		rebuilt = append(rebuilt, l)
	}
	return bytes.Join(rebuilt, []byte("\n"))
}

// maskProviderData unmarshals the data line into a generic JSON tree, locates
// the per-provider carrier field, applies the local mask spans, and re-
// marshals. Returns (out, true) when masking produced valid output; (nil,
// false) when the carrier shape is unrecognized (caller falls back to raw).
func maskProviderData(path string, dataLine []byte, local []engine.Finding) ([]byte, bool) {
	var root interface{}
	if err := json.Unmarshal(dataLine, &root); err != nil {
		return nil, false
	}
	switch {
	case strings.HasSuffix(path, "/chat/completions"):
		if maskOpenAIChat(root, local) {
			out, err := json.Marshal(root)
			if err == nil {
				return out, true
			}
		}
	case strings.HasSuffix(path, "/messages"):
		if maskAnthropic(root, local) {
			out, err := json.Marshal(root)
			if err == nil {
				return out, true
			}
		}
	case strings.HasSuffix(path, "/responses"):
		if maskOpenAIResponses(root, local) {
			out, err := json.Marshal(root)
			if err == nil {
				return out, true
			}
		}
	}
	return nil, false
}

// maskOpenAIChat masks choices[].delta.content. Returns true if masking was
// applied to at least one choice. Multi-choice events mean content spans map
// across choices; we distribute local spans per-choice using the cumulative
// offset built from each choice's content length. Spans straddling a choice
// boundary are clipped to the containing choice (rare in practice).
func maskOpenAIChat(root interface{}, local []engine.Finding) bool {
	m, ok := root.(map[string]interface{})
	if !ok {
		return false
	}
	choicesRaw, ok := m["choices"]
	if !ok {
		return false
	}
	choices, ok := choicesRaw.([]interface{})
	if !ok {
		return false
	}
	offset := 0
	applied := false
	for _, c := range choices {
		cchoice, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		deltaRaw, ok := cchoice["delta"]
		if !ok {
			continue
		}
		delta, ok := deltaRaw.(map[string]interface{})
		if !ok {
			continue
		}
		contentRaw, ok := delta["content"]
		if !ok {
			continue
		}
		content, ok := contentRaw.(string)
		if !ok {
			continue
		}
		masked, _, hadOverlap := maskStringOffsets(content, local, offset)
		if hadOverlap {
			delta["content"] = masked
			applied = true
		}
		offset += len(content)
	}
	return applied
}

// maskAnthropic masks delta.text on a content_block_delta event.
func maskAnthropic(root interface{}, local []engine.Finding) bool {
	m, ok := root.(map[string]interface{})
	if !ok {
		return false
	}
	deltaRaw, ok := m["delta"]
	if !ok {
		return false
	}
	delta, ok := deltaRaw.(map[string]interface{})
	if !ok {
		return false
	}
	contentRaw, ok := delta["text"]
	if !ok {
		return false
	}
	content, ok := contentRaw.(string)
	if !ok {
		return false
	}
	masked, _, hadOverlap := maskStringOffsets(content, local, 0)
	if !hadOverlap {
		return false
	}
	delta["text"] = masked
	return true
}

// maskOpenAIResponses masks the top-level delta string.
func maskOpenAIResponses(root interface{}, local []engine.Finding) bool {
	m, ok := root.(map[string]interface{})
	if !ok {
		return false
	}
	contentRaw, ok := m["delta"]
	if !ok {
		return false
	}
	content, ok := contentRaw.(string)
	if !ok {
		return false
	}
	masked, _, hadOverlap := maskStringOffsets(content, local, 0)
	if !hadOverlap {
		return false
	}
	m["delta"] = masked
	return true
}

// maskStringOffsets applies local mask spans to content. Spans are local
// offsets within the carrier; baseOffset is added to each span start/end to
// map it to content-local coordinates when content is part of a larger
// decoded concatenation (the OpenAI chat multi-choice case). Spans beyond
// the string's range are clipped; spans partially overlapping are clipped to
// the overlap.
func maskStringOffsets(content string, local []engine.Finding, baseOffset int) (string, bool, bool) {
	type span struct{ start, end int }
	var spans []span
	for _, s := range local {
		start := s.Start - baseOffset
		end := s.End - baseOffset
		if start < 0 {
			start = 0
		}
		if end > len(content) {
			end = len(content)
		}
		if start < end {
			spans = append(spans, span{start, end})
		}
	}
	if len(spans) == 0 {
		return content, false, false
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
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
	runes := []byte(content)
	for _, s := range merged {
		for i := s.start; i < s.end; i++ {
			runes[i] = '*'
		}
	}
	return string(runes), true, true
}

func (ss *streamScanner) finalize(w io.Writer) (ledger.Verdict, []ledger.Finding, []string) {
	// Feed any remaining un-fed bytes (hold-back region), then drain pending
	// candidates through StreamScan.Finalize. This picks up findings from the
	// tail end of the stream that the chunk-by-chunk Feed calls hadn't yet
	// resolved because their max_match_len window extended past the last chunk
	// end (D-16), plus any deferred IBAN starts. Both the tail feed and the
	// final drain route through ingest, so a block-action secret that only
	// resolves at end-of-stream is still latched as blocked (and its content
	// withheld below) rather than flushed in the clear. Findings are deduped
	// against the seen set inside StreamScan.
	if !ss.blocked && ss.eng != nil && ss.streamScan != nil {
		// Feed held-back region (since the last Feed).
		if ss.feededDecodedLen < len(ss.decoded) {
			tail := ss.decoded[ss.feededDecodedLen:]
			findings, _ := ss.streamScan.Feed(tail, ss.decoded)
			ss.feededDecodedLen = len(ss.decoded)
			ss.ingest(findings)
		}
		// Final drain — scan all pending candidates against the final
		// reassembled buffer, even if their window extends past the end.
		if !ss.blocked {
			ss.ingest(ss.streamScan.Finalize(ss.decoded))
		}
	}

	if ss.blocked {
		return ledger.VerdictBlocked, ss.summaryFindings(), ss.unscannedFields
	}

	if len(ss.pending) > 0 {
		ss.flushMasked(w, ss.pending)
		ss.pending = nil
	}

	verdict := ledger.VerdictForwarded
	if len(ss.maskSpans) > 0 {
		verdict = ledger.VerdictMasked
	}
	return verdict, ss.summaryFindings(), ss.unscannedFields
}

// summaryFindings aggregates allFindings into the ledger shape (class ×
// action → count). No regex re-runs — strictly an aggregation over what
// StreamScan produced incrementally.
func (ss *streamScanner) summaryFindings() []ledger.Finding {
	classActions := map[string]map[string]int{}
	for _, f := range ss.allFindings {
		result := ss.evaluator.Evaluate(f.Class, ss.dest, f.Confidence)
		action := string(result.Action)
		if _, ok := classActions[f.Class]; !ok {
			classActions[f.Class] = map[string]int{}
		}
		classActions[f.Class][action]++
	}
	var ledgerFindings []ledger.Finding
	for cls, actions := range classActions {
		for action, count := range actions {
			ledgerFindings = append(ledgerFindings, ledger.Finding{
				Class:  cls,
				Count:  count,
				Action: action,
			})
		}
	}
	return ledgerFindings
}

func readSSEChunks(r io.Reader) func() (advance int, token []byte, err error) {
	var buf []byte
	return func() (int, []byte, error) {
		for {
			if i := bytes.Index(buf, []byte("\n\n")); i >= 0 {
				token := buf[:i+2]
				buf = buf[i+2:]
				return len(token), token, nil
			}
			chunk := make([]byte, 32*1024)
			n, err := r.Read(chunk)
			if n > 0 {
				buf = append(buf, chunk[:n]...)
				continue
			}
			if err == io.EOF && len(buf) > 0 {
				token := buf
				buf = nil
				return len(token), token, io.EOF
			}
			return 0, nil, err
		}
	}
}

// parseSSEToken extracts event/data from a raw SSE frame. hasComment reports
// whether the frame carried a non-empty SSE comment line (`: <text>`) — per
// spec, comments are never payload-bearing and are typically empty keep-alive
// pings (`:\n` or `: \n`, which don't set hasComment), but SSE syntax doesn't
// forbid a comment line from carrying arbitrary text. That text is
// structurally invisible to this parser (no event/data field captures it), so
// the caller must not treat its absence from `data` as "nothing was here" —
// see the D-21-pattern unscanned-field flag at the call site.
func parseSSEToken(token []byte) (event string, data []byte, hasComment bool) {
	// per the SSE spec: multi-line `data:` payloads are concatenated with
	// `\n` separators; a single trailing `\n` is stripped.
	firstData := true
	for _, raw := range bytes.Split(token, []byte("\n")) {
		line := bytes.TrimSpace(raw)
		switch {
		case bytes.HasPrefix(line, []byte("event: ")):
			event = string(bytes.TrimSpace(line[7:]))
		case bytes.HasPrefix(line, []byte("data: ")):
			if !firstData {
				data = append(data, '\n')
			}
			firstData = false
			data = append(data, bytes.TrimSpace(line[6:])...)
		case bytes.HasPrefix(line, []byte("data:")):
			if !firstData {
				data = append(data, '\n')
			}
			firstData = false
			data = append(data, bytes.TrimSpace(line[5:])...)
		case bytes.HasPrefix(line, []byte(":")):
			if len(bytes.TrimSpace(line[1:])) > 0 {
				hasComment = true
			}
		}
	}
	return event, data, hasComment
}

// writeStreamBlockEvent wraps the provider-shaped block error body — the
// SAME body BlockErrorForPath builds for the non-streaming path — in an SSE
// error event. Streaming only ever scans responses (requests are never
// streamed), so "response" is correct here by
// construction; reusing BlockErrorForPath instead of hand-rolling a second
// copy of the message/JSON-shape logic keeps the two block paths from
// silently drifting apart.
func writeStreamBlockEvent(w io.Writer, path string, detail policy.BlockDetail) {
	_, eventPayload := policy.BlockErrorForPath(path, "response", detail)
	sseBlock := "event: error\ndata: " + string(eventPayload) + "\n\n"
	w.Write([]byte(sseBlock))
}

func (g *Gateway) handleStreamingResponse(w http.ResponseWriter, upstreamResp *http.Response, reqID, dest, model, path string) {
	ss := newStreamScanner(g.engine, g.evaluator, dest, path, reqID)

	respHeaders := upstreamResp.Header.Clone()
	removeHopByHopHeaders(respHeaders)
	respHeaders.Del("Content-Length")
	copyHeaders(w.Header(), respHeaders)
	w.WriteHeader(upstreamResp.StatusCode)
	flusher, canFlush := w.(http.Flusher)

	next := readSSEChunks(upstreamResp.Body)
	ledgerWritten := false

	for {
		_, token, err := next()
		if err != nil && len(token) == 0 {
			if err != io.EOF {
				log.Printf("stream read error: %v", err)
			}
			break
		}

		eventType, data, hasComment := parseSSEToken(token)
		// No special-casing here for "no data" or the OpenAI `[DONE]`
		// sentinel: every token — including a bare SSE comment/keep-alive
		// with no `data:` line, and the `[DONE]` sentinel real client SDKs
		// key off to detect stream completion — must still reach the client
		// (byte-identical passthrough, D-20). extractStreamDelta already
		// handles non-JSON/non-delta data by returning an empty
		// streamTextResult (json.Unmarshal fails cleanly), which addEvent
		// turns into a zero-width decoded span: nothing to scan or hold,
		// so it flushes on the very next scanAndFlush like any other
		// control event (Anthropic's message_stop, OpenAI Responses'
		// non-delta status events, etc. already relied on this same path).
		extracted := extractStreamDelta(path, eventType, data)
		if hasComment {
			// A non-empty SSE comment line (`: <text>`) is forwarded
			// byte-identical like any other content-free control event, but
			// unlike event/data fields it is never parsed or scanned — no
			// field captures its text. Flag it the same way an
			// adapter-unrecognized JSON field is flagged (D-21 fail-open
			// with visibility) rather than silently trusting no legitimate
			// provider ever puts real content there.
			extracted.unscanned = append(extracted.unscanned, "sse:comment")
		}
		ss.addEvent(token, extracted)
		ss.scanAndFlush(w)

		if ss.blocked {
			writeStreamBlockEvent(w, path, *ss.blockDetail)
			if canFlush {
				flusher.Flush()
			}
			g.emitStreamLedger(reqID, "response", dest, model, "", time.Now(), ss.summaryFindings(), ledger.VerdictBlocked, ss.unscannedFields)
			ledgerWritten = true
			return
		}

		if canFlush {
			flusher.Flush()
		}
	}

	if !ledgerWritten {
		verdict, findings, unscanned := ss.finalize(w)
		// A block can first surface at end-of-stream (its max_match_len window
		// needed the final bytes). finalize withholds the held-back content in
		// that case; emit the provider-shaped block event so the client sees a
		// blocked response rather than a silently truncated stream.
		if verdict == ledger.VerdictBlocked && ss.blockDetail != nil {
			writeStreamBlockEvent(w, path, *ss.blockDetail)
		}
		if canFlush {
			flusher.Flush()
		}
		g.emitStreamLedger(reqID, "response", dest, model, "", time.Now(), findings, verdict, unscanned)
	}
}

func (g *Gateway) emitStreamLedger(reqID, direction, dest, model, bodySHA string, ts time.Time, findings []ledger.Finding, verdict ledger.Verdict, unscannedFields []string) {
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
