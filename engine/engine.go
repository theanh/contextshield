package engine

import (
	"fmt"
	"regexp"
	"sort"
)

const (
	prefilterLiteral = "literal"
	prefilterDigit   = "digit"
	prefilterIBAN    = "iban"
)

type Matcher struct {
	rules      []compiledRule
	automaton  *automaton
	digitRules []int
	ibanRules  []int
}

type compiledRule struct {
	rule       Rule
	pattern    *regexp.Regexp
	confidence float64
}

func (m *Matcher) Rules() []Rule {
	rules := make([]Rule, len(m.rules))
	for i, cr := range m.rules {
		rules[i] = cr.rule
	}
	return rules
}

func NewMatcher(rules []Rule) (*Matcher, error) {
	m := &Matcher{
		rules:     make([]compiledRule, 0, len(rules)),
		automaton: newAutomaton(),
	}

	for _, rule := range rules {
		if err := validateRule(rule); err != nil {
			return nil, err
		}
		pattern, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", rule.ID, err)
		}
		confidence := rule.Confidence
		if confidence == 0 {
			confidence = 1.0
		}
		idx := len(m.rules)
		m.rules = append(m.rules, compiledRule{
			rule:       rule,
			pattern:    pattern,
			confidence: confidence,
		})

		switch rule.Prefilter {
		case "", prefilterLiteral:
			if len(rule.Keywords) == 0 {
				return nil, fmt.Errorf("rule %q: literal prefilter requires at least one keyword", rule.ID)
			}
			for _, keyword := range rule.Keywords {
				m.automaton.add(foldASCII([]byte(keyword)), idx)
			}
		case prefilterDigit:
			m.digitRules = append(m.digitRules, idx)
		case prefilterIBAN:
			m.ibanRules = append(m.ibanRules, idx)
		default:
			return nil, fmt.Errorf("rule %q: unsupported prefilter %q", rule.ID, rule.Prefilter)
		}
	}
	m.automaton.build()
	return m, nil
}

func Find(text []byte, rules []Rule) ([]Finding, error) {
	matcher, err := NewMatcher(rules)
	if err != nil {
		return nil, err
	}
	return matcher.Find(text), nil
}

func (m *Matcher) Find(text []byte) []Finding {
	findings := []Finding{}
	seen := map[candidateKey]struct{}{}
	state := 0

	for pos, b := range text {
		state = m.automaton.step(state, lowerASCII(b))
		for _, hit := range m.automaton.nodes[state].out {
			start := pos - hit.length + 1
			findings = m.scanRule(text, hit.ruleIndex, start, findings, seen)
		}

		if isDigitCandidateStart(text, pos) {
			for _, ruleIndex := range m.digitRules {
				findings = m.scanRule(text, ruleIndex, pos, findings, seen)
			}
		}
		if isIBANCandidateStart(text, pos) {
			for _, ruleIndex := range m.ibanRules {
				findings = m.scanRule(text, ruleIndex, pos, findings, seen)
			}
		}
	}

	sortFindings(findings)
	return findings
}

// sortFindings orders findings by (start, end, ruleID) — the canonical order
// shared by Find, Feed, and Finalize so streaming and non-streaming output
// match byte-for-byte.
func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Start != findings[j].Start {
			return findings[i].Start < findings[j].Start
		}
		if findings[i].End != findings[j].End {
			return findings[i].End < findings[j].End
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}

// StreamScan is the streaming counterpart of Find, per D-16's automaton-state
// hold-back. The Matcher stays stateless; StreamScan wraps the automaton state,
// the running byte offset, and the seen-findings dedupe set so chunks can be
// fed incrementally as the gateway decodes SSE/jJSON events. Each call:
//   - advances the automaton over the chunk,
//   - returns findings completed within this chunk (sorted, deduped),
//   - returns the longest live partial-match length at the current state
//     (the deepest keyword prefix still in play). The gateway flushes every
//     decoded byte before this position and holds the rest.
//
// Worst case hold = max(max_match_len) over rules whose anchors could still
// extend from the current state, NOT max(max_match_len) over all rules — that
// is the distinction D-16 makes against the rejected fixed-window approach.
// At the root state (no live partial — common on prose) hold is 0.
//
// digit/IBAN prefilters don't go through the automaton; their worst case
// hold for streaming purposes is the max MaxMatchLen across their rule sets
// (the candidate window). They activate only at digit/IBAN boundary starts,
// so a streaming caller needs to hold at most max_match_len bytes after such
// a boundary until the rule either matches or the value exceeds max_match_len.
// The caller always sees holdLen >= the digit/IBAN worst case for the bytes
// in the just-fed chunk, with the automaton's literal hold overlapping.
type StreamScan struct {
	m     *Matcher
	state int
	// absoluteOffset tracks total bytes fed so far so findings carry absolute
	// offsets into the reassembled stream text, matching the non-streaming
	// Find contract.
	absoluteOffset int
	// pendingCandidates are digit/IBAN candidate starts whose max_match_len
	// windows extend past the current end of fed bytes. They must be retried
	// when more bytes arrive (the regex/validator can only confirm once the
	// window is fully available). Multiple candidates can be pending
	// simultaneously when several digit/IBAN boundaries occur in the same
	// chunk whose windows all exceed the chunk end.
	pendingCandidates []pendingCandidate
	// pendingLiteral are literal-prefilter candidates (e.g., "AKIA",
	// "TESTKEY") whose AC out fired but whose regex window extends past the
	// current end of reassembled. Same defer semantics as pendingCandidates:
	// retry when the next Feed brings more bytes.
	pendingLiteral []pendingLiteralCandidate
	// deferredIBANStarts are absolute positions at which an IBAN candidate
	// start check couldn't complete because pos+3 extended past the
	// reassembled buffer at the time the byte was fed. The next Feed call,
	// with more bytes, re-runs isIBANCandidateStart and either promotes to
	// pendingCandidates or discards.
	deferredIBANStarts []int
	seen               map[candidateKey]struct{}
}

type pendingLiteralCandidate struct {
	start     int
	ruleIndex int
}

type pendingCandidate struct {
	start int
	kind  byte // 'd' = digit, 'i' = iban
}

// NewStreamScan returns a fresh streaming scan state. Findings offsets are
// absolute in the reassembled byte stream (offset 0 = first byte of the
// first Feed call on this StreamScan).
func (m *Matcher) NewStreamScan() *StreamScan {
	return &StreamScan{m: m, seen: map[candidateKey]struct{}{}}
}

// Feed advances the scan over chunk and returns findings completed within
// this chunk, plus the longest live partial-match length at the current
// automaton state (the hold-back length for the gateway).
//
// reassembled is the full decoded text fed to this StreamScan so far,
// including the current chunk. The gateway owns this buffer (it lives in
// streamScanner.decoded); the engine stays buffer-free (Invariant 6).
// reassembled must be at least chunkStart+len(chunk) bytes; offsets returned
// in findings are absolute in reassembled (matching the non-streaming Find).
//
// Findings are sorted by (start, end, ruleID) and deduped against findings
// from earlier chunks on the same StreamScan.
func (s *StreamScan) Feed(chunk []byte, reassembled []byte) (findings []Finding, holdLen int) {
	findings = []Finding{}
	if s.m == nil {
		return findings, 0
	}
	if len(chunk) == 0 {
		// Nothing new to scan (e.g. the gateway fed a control event that
		// decoded to zero bytes — an SSE keep-alive with no `data:` line, or
		// the `[DONE]` sentinel). This must NOT collapse the hold-back to 0:
		// any candidate already pending from an earlier Feed call is still
		// exactly as pending as it was, and the automaton's live partial
		// match (if mid-keyword) hasn't gone anywhere either. Recompute from
		// current state rather than returning a bare 0, or the gateway
		// flushes an already-buffered, not-yet-resolved secret prefix the
		// moment a zero-content event arrives between real content chunks.
		return findings, s.holdLen(s.absoluteOffset)
	}
	if len(reassembled) < s.absoluteOffset+len(chunk) {
		// Caller didn't keep the decoded buffer in sync; nothing safe to do
		// but report no findings and let the gateway's finalize pass catch
		// anything missed via a fresh non-streaming Find on the full buffer.
		return findings, 0
	}

	chunkStart := s.absoluteOffset
	chunkEnd := chunkStart + len(chunk)

	// Drain pending candidates from previous chunks. Those whose windows
	// now fit are scanned; those still short of bytes stay pending.
	if len(s.pendingCandidates) > 0 {
		var remaining []pendingCandidate
		for _, pc := range s.pendingCandidates {
			maxLen := s.m.maxMatchLenFor(pc.kind)
			if pc.start+scanWindowLen(maxLen) <= len(reassembled) {
				for _, ri := range s.m.ruleIndexesFor(pc.kind) {
					findings = s.scanRule(findings, ri, pc.start, reassembled)
				}
			} else {
				remaining = append(remaining, pc)
			}
		}
		s.pendingCandidates = remaining
	}

	// Re-evaluate IBAN candidate starts that we deferred at the end of the
	// previous chunk because pos+3 extended past reassembled at registration
	// time. Now we have more bytes.
	if len(s.deferredIBANStarts) > 0 {
		var stillDeferred []int
		for _, pos := range s.deferredIBANStarts {
			switch streamIBANCandidateDecision(reassembled, pos) {
			case 1:
				s.processIBANCandidate(pos, len(reassembled), reassembled, &findings)
			case 2:
				stillDeferred = append(stillDeferred, pos)
			}
		}
		s.deferredIBANStarts = stillDeferred
	}

	// Drain pending literal candidates whose regex windows now fit. Those
	// still short of bytes stay pending.
	if len(s.pendingLiteral) > 0 {
		var remaining []pendingLiteralCandidate
		for _, pc := range s.pendingLiteral {
			rule := s.m.rules[pc.ruleIndex]
			if pc.start+scanWindowLen(rule.rule.MaxMatchLen) <= len(reassembled) {
				findings = s.scanRule(findings, pc.ruleIndex, pc.start, reassembled)
			} else {
				remaining = append(remaining, pc)
			}
		}
		s.pendingLiteral = remaining
	}

	for i := 0; i < len(chunk); i++ {
		pos := chunkStart + i
		b := chunk[i]
		s.state = s.m.automaton.step(s.state, lowerASCII(b))
		for _, hit := range s.m.automaton.nodes[s.state].out {
			start := pos - hit.length + 1
			// Literal-prefilter rules scan their regex window at AC out
			// time. If the window (start+max_match_len, plus the
			// right-context byte scanRule needs for a trailing boundary)
			// extends past the current end of reassembled, defer the
			// candidate to pendingLiteral — the next Feed (more bytes) will
			// scan it. Without this, a partial match split across chunks
			// (e.g., "TESTKEYAB" then "CDEFGHIJKLMNOP") would be missed: the
			// AC out fired in chunk 1 with a too-short window, and chunk 2's
			// bytes don't re-trigger the anchor.
			rule := s.m.rules[hit.ruleIndex]
			windowEnd := start + scanWindowLen(rule.rule.MaxMatchLen)
			if windowEnd <= len(reassembled) {
				findings = s.scanRule(findings, hit.ruleIndex, start, reassembled)
			} else {
				s.pendingLiteral = append(s.pendingLiteral, pendingLiteralCandidate{
					start:     start,
					ruleIndex: hit.ruleIndex,
				})
			}
		}

		// Digit/IBAN candidate starts. The candidate's max_match_len window
		// may extend past the current chunk end — defer it to pending. The
		// boundary helpers must see reassembled[pos-1] across chunk edges, so
		// they take the full reassembled buffer at the absolute pos.
		if isDigitCandidateStart(reassembled, pos) {
			if s.canResolveNow(pos, len(reassembled), 'd') {
				for _, ri := range s.m.digitRules {
					findings = s.scanRule(findings, ri, pos, reassembled)
				}
			} else {
				s.pendingCandidates = append(s.pendingCandidates, pendingCandidate{start: pos, kind: 'd'})
			}
		}
		switch streamIBANCandidateDecision(reassembled, pos) {
		case 1:
			s.processIBANCandidate(pos, len(reassembled), reassembled, &findings)
		case 2:
			s.deferredIBANStarts = append(s.deferredIBANStarts, pos)
		}
	}

	s.absoluteOffset = chunkEnd

	sortFindings(findings)

	holdLen = s.holdLen(chunkEnd)
	return findings, holdLen
}

// Finalize drains any remaining pending candidates (and deferred IBAN
// starts) against the final reassembled buffer. The max_match_len window
// may extend past the end of the stream; scanRule truncates the window to
// len(reassembled) and lets the regex/validators confirm or reject.
//
// Returns findings not yet emitted by Feed (sorted, deduped via seen set).
// The gateway calls this at end-of-stream to ensure no candidate is missed
// because its window required more bytes than the stream ever produced.
func (s *StreamScan) Finalize(reassembled []byte) []Finding {
	findings := []Finding{}
	if s.m == nil {
		return findings
	}

	// Re-evaluate deferred IBAN starts at final buffer length.
	for _, pos := range s.deferredIBANStarts {
		if streamIBANCandidateDecision(reassembled, pos) == 1 {
			s.pendingCandidates = append(s.pendingCandidates, pendingCandidate{start: pos, kind: 'i'})
		}
	}
	s.deferredIBANStarts = nil

	// Drain pending literal candidates (window may be shorter than
	// max_match_len; scanRule truncates the window to len(reassembled)).
	for _, pc := range s.pendingLiteral {
		findings = s.scanRule(findings, pc.ruleIndex, pc.start, reassembled)
	}
	s.pendingLiteral = nil

	// Drain all pending, scanning with whatever reassembled is available.
	for _, pc := range s.pendingCandidates {
		for _, ri := range s.m.ruleIndexesFor(pc.kind) {
			findings = s.scanRule(findings, ri, pc.start, reassembled)
		}
	}
	s.pendingCandidates = nil
	sortFindings(findings)
	return findings
}

// canResolveNow reports whether the candidate at candidateStart of the given
// kind has its full scan window fully available in reassembled up to
// currentEnd — max_match_len for the value plus the right-context byte scanRule
// needs to resolve a trailing boundary assertion (rightContextBytes / D-26).
func (s *StreamScan) canResolveNow(candidateStart, currentEnd int, kind byte) bool {
	return candidateStart+scanWindowLen(s.m.maxMatchLenFor(kind)) <= currentEnd
}

// processIBANCandidate scans an IBAN candidate at absolute candidateStart
// against all IBAN rules. If its max_match_len window fits in reassembled,
// scan immediately; otherwise defer to pending.
func (s *StreamScan) processIBANCandidate(candidateStart, currentEnd int, reassembled []byte, findings *[]Finding) {
	if s.canResolveNow(candidateStart, currentEnd, 'i') {
		for _, ri := range s.m.ibanRules {
			*findings = s.scanRule(*findings, ri, candidateStart, reassembled)
		}
	} else {
		s.pendingCandidates = append(s.pendingCandidates, pendingCandidate{start: candidateStart, kind: 'i'})
	}
}

// streamIBANCandidateDecision triages a position as an IBAN candidate.
//   - 0 = definitively not a candidate (boundary or first two chars fail).
//   - 1 = candidate (full 4-char check passes).
//   - 2 = defer (promising prefix confirmed but bytes at pos+2 or pos+3 not
//     yet available).
func streamIBANCandidateDecision(text []byte, pos int) int {
	if pos < 0 || pos >= len(text) {
		return 0
	}
	if !isUpper(text[pos]) {
		return 0
	}
	if pos > 0 && isAlphaNum(text[pos-1]) {
		return 0
	}
	// pos is uppercase and prev is non-alphanum (or pos==0). Now check
	// pos+1, pos+2, pos+3 against the IBAN shape (two upper, two digit).
	if pos+1 >= len(text) {
		// Can't yet check text[pos+1] (uppercase second country char).
		return 2
	}
	if !isUpper(text[pos+1]) {
		return 0
	}
	if pos+2 >= len(text) || pos+3 >= len(text) {
		return 2
	}
	if isDigit(text[pos+2]) && isDigit(text[pos+3]) {
		return 1
	}
	return 0
}

// holdLen is the number of trailing bytes the gateway must hold back before
// flushing: the longest still-uncertain region ending at currentEnd.
//
// A pending literal/digit/IBAN candidate at pc.start is unresolved precisely
// because its max_match_len window extends past currentEnd, so its match could
// begin as early as pc.start — the whole [pc.start, currentEnd) region is still
// in play and must be held. The hold contribution is therefore currentEnd -
// pc.start (the already-buffered uncertain prefix), NOT windowEnd - currentEnd
// (the not-yet-arrived tail). Holding only the tail flushes the buffered prefix
// of a secret split across chunks — the exact leak D-16's hold-back exists to
// prevent. This mirrors the automaton branch, whose statePartialMatchLen is
// likewise the count of already-consumed prefix bytes.
func (s *StreamScan) holdLen(currentEnd int) int {
	hold := s.m.automaton.statePartialMatchLen(s.state)
	for _, pc := range s.pendingCandidates {
		if uncertain := currentEnd - pc.start; uncertain > hold {
			hold = uncertain
		}
	}
	for _, pc := range s.pendingLiteral {
		if uncertain := currentEnd - pc.start; uncertain > hold {
			hold = uncertain
		}
	}
	return hold
}

// scanRule resolves the candidate at absoluteStart against rule ruleIndex
// using the caller-provided window bytes. The gateway owns the decoded
// buffer that backs these offsets, so it passes the [start, start+maxMatchLen)
// window in directly. This keeps the engine buffer-free in streaming mode
// (Invariant 6) and also makes the hold-back math auditable per chunk. The
// windowing/regex/dedupe/validator logic is identical to the non-streaming
// path, so it delegates to Matcher.scanRule with the StreamScan's seen set.
func (s *StreamScan) scanRule(findings []Finding, ruleIndex, absoluteStart int, reassembled []byte) []Finding {
	return s.m.scanRule(reassembled, ruleIndex, absoluteStart, findings, s.seen)
}

// ruleIndexesFor returns the per-kind rule index slice.
func (m *Matcher) ruleIndexesFor(kind byte) []int {
	switch kind {
	case 'd':
		return m.digitRules
	case 'i':
		return m.ibanRules
	}
	return nil
}

// maxMatchLenFor returns the largest max_match_len across rules of the given
// prefilter kind. Returns 0 if there are no such rules.
func (m *Matcher) maxMatchLenFor(kind byte) int {
	var maxLen int
	for _, ri := range m.ruleIndexesFor(kind) {
		if l := m.rules[ri].rule.MaxMatchLen; l > maxLen {
			maxLen = l
		}
	}
	return maxLen
}

type candidateKey struct {
	ruleIndex int
	start     int
	end       int
}

// leftContextBytes and rightContextBytes are the real neighbor bytes the
// candidate window carries on each side of a candidate so zero-width boundary
// assertions (\b in particular) resolve against the true adjacent characters
// instead of the slice edge. Go's regexp treats the start and end of the given
// slice as a word boundary, so a window of exactly [start, start+max_match_len)
// makes a rule like \bAKIA[0-9A-Z]{16}\b match falsely at BOTH edges:
//   - left:  "MAKIA…" — \b fires at the window start though the true previous
//            byte ('M') is a word char, so there is no real boundary;
//   - right: "AKIA"+17 chars — max_match_len (20) truncates the window exactly
//            at the byte the trailing \b must inspect, so \b fires at the
//            window end though the true next byte is a word char (over-length).
// One byte each side is sufficient: \b depends only on the immediately adjacent
// character and RE2 has no lookbehind, so no wider left context can change a
// match; the trailing anchor likewise needs to see only the single byte past a
// maximal value. The window stays bounded at max_match_len+2 (Invariant 5 /
// D-16 keep it constant-bounded); match offsets are shifted back to absolute
// coordinates below. Because scanRule can now inspect the byte at
// start+max_match_len, the streaming caller must have that byte buffered before
// a candidate resolves — see rightContextBytes' use in StreamScan.Feed (D-26).
const (
	leftContextBytes  = 1
	rightContextBytes = 1
)

// scanWindowLen is the number of bytes from a candidate's start that scanRule
// needs available to resolve it: the value window (max_match_len) plus the
// right-context byte for a trailing boundary assertion. scanRule's window end
// and every streaming "is this candidate resolvable yet?" check derive from
// this one definition, so streaming resolution and the non-streaming window
// can never silently disagree (which would break byte-identical equivalence).
func scanWindowLen(maxMatchLen int) int {
	return maxMatchLen + rightContextBytes
}

func (m *Matcher) scanRule(text []byte, ruleIndex, start int, findings []Finding, seen map[candidateKey]struct{}) []Finding {
	if start < 0 || start >= len(text) {
		return findings
	}
	rule := m.rules[ruleIndex]
	windowStart := start - leftContextBytes
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := start + scanWindowLen(rule.rule.MaxMatchLen)
	if windowEnd > len(text) {
		windowEnd = len(text)
	}
	window := text[windowStart:windowEnd]
	indexes := rule.pattern.FindSubmatchIndex(window)
	if indexes == nil {
		return findings
	}
	// The prefilter anchored this candidate at `start`; the left-context byte
	// is there only so boundary assertions resolve, never as match content. A
	// whole-match (group 0) that begins before `start` means the pattern
	// consumed the context byte — a rule whose regex isn't anchored at its
	// prefilter position. Reject it so a finding's offsets stay attributed to
	// the candidate instead of shifting into the neighbor byte. Every current
	// rule's match begins exactly at `start` (\b is zero-width; keyword/digit
	// anchors sit at the candidate), so this never fires today.
	if windowStart+indexes[0] < start {
		return findings
	}

	group := rule.rule.MatchGroup
	if group < 0 || group*2+1 >= len(indexes) || indexes[group*2] < 0 {
		group = 0
	}
	matchStart := windowStart + indexes[group*2]
	matchEnd := windowStart + indexes[group*2+1]
	if matchStart == matchEnd {
		return findings
	}
	key := candidateKey{ruleIndex: ruleIndex, start: matchStart, end: matchEnd}
	if _, ok := seen[key]; ok {
		return findings
	}
	if !rule.validatorsPass(text[matchStart:matchEnd]) {
		return findings
	}
	seen[key] = struct{}{}
	return append(findings, Finding{
		RuleID:     rule.rule.ID,
		Class:      rule.rule.Class,
		Start:      matchStart,
		End:        matchEnd,
		Confidence: rule.confidence,
	})
}

func (r compiledRule) validatorsPass(value []byte) bool {
	for _, validator := range r.rule.Validators {
		if !validateCandidate(validator, value) {
			return false
		}
	}
	return true
}

func validateRule(rule Rule) error {
	switch {
	case rule.ID == "":
		return fmt.Errorf("rule missing id")
	case rule.Class == "":
		return fmt.Errorf("rule %q: missing class", rule.ID)
	case rule.Pattern == "":
		return fmt.Errorf("rule %q: missing pattern", rule.ID)
	case rule.MaxMatchLen <= 0:
		return fmt.Errorf("rule %q: max_match_len is required", rule.ID)
	}
	if rule.Confidence < 0 || rule.Confidence > 1 {
		return fmt.Errorf("rule %q: confidence must be between 0 and 1", rule.ID)
	}
	return nil
}

func isDigitCandidateStart(text []byte, pos int) bool {
	if text[pos] < '0' || text[pos] > '9' {
		return false
	}
	if pos == 0 {
		return true
	}
	prev := text[pos-1]
	return prev < '0' || prev > '9'
}

func isIBANCandidateStart(text []byte, pos int) bool {
	if pos+3 >= len(text) {
		return false
	}
	if pos > 0 && isAlphaNum(text[pos-1]) {
		return false
	}
	return isUpper(text[pos]) && isUpper(text[pos+1]) && isDigit(text[pos+2]) && isDigit(text[pos+3])
}

func isUpper(b byte) bool {
	return b >= 'A' && b <= 'Z'
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isAlphaNum(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || isDigit(b)
}

func foldASCII(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		out[i] = lowerASCII(b)
	}
	return out
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
