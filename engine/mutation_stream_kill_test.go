package engine

import (
	"testing"
)

// This file hardens the engine's automaton, streaming (StreamScan), and
// match-group resolution paths against surviving mutants found by gremlins.
// The existing mutation_kill_test.go pins the pure byte/validator helpers; this
// one pins the parts the black-box equivalence tests leave loose — internal
// boundary math and per-chunk (Feed-time) emission timing that Finalize would
// otherwise mask. White-box (package engine), data-provider style, no logic.

// --- Aho-Corasick fail links -----------------------------------------------

// TestAutomatonFailLinkOverlap pins the fail-link construction in build().
// "yz" in "xyz" is only reachable via the fail link node("xy") -> node("y") ->
// node("yz"). If the root-fallback branch (fail == 0 { ... ok && next != child })
// is broken, the automaton drops "yz". Grade the outcome: both keywords found.
func TestAutomatonFailLinkOverlap(t *testing.T) {
	rules := []Rule{
		{ID: "xy", Class: "secret.test", Pattern: `xy`, MaxMatchLen: 2, Keywords: []string{"xy"}},
		{ID: "yz", Class: "secret.test", Pattern: `yz`, MaxMatchLen: 2, Keywords: []string{"yz"}},
	}
	m, err := NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, f := range m.Find([]byte("xyz")) {
		found[f.RuleID] = true
	}
	if !found["xy"] || !found["yz"] {
		t.Fatalf("want both xy and yz via fail links, got %v", found)
	}
}

// TestStatePartialMatchLenBounds pins the out-of-range guard in
// statePartialMatchLen: negative state and state == len(nodes) must clamp to 0
// (not index the nodes slice). Mutating the guard's `||` to `&&` or `>=` to `>`
// turns these into panics.
func TestStatePartialMatchLenBounds(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "r", Class: "c", Pattern: `AKIA`, MaxMatchLen: 4, Keywords: []string{"AKIA"}}})
	if err != nil {
		t.Fatal(err)
	}
	a := m.automaton
	cases := []struct {
		name  string
		state int
		want  int
	}{
		{"negative state clamps to zero", -1, 0},
		{"state at len(nodes) clamps to zero", len(a.nodes), 0},
		{"root state is zero", 0, 0},
		{"depth-one state after first anchor byte", 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.statePartialMatchLen(tc.state); got != tc.want {
				t.Fatalf("statePartialMatchLen(%d) = %d, want %d", tc.state, got, tc.want)
			}
		})
	}
}

// --- canonical finding order ------------------------------------------------

// TestFindingsSortedByStart pins the primary sort key in sortFindings. Two
// findings that END at the same offset but START at different offsets must come
// back in start order. Mutating the `Start != Start` guard to `==` drops the
// start comparison and re-orders them by ruleID.
func TestFindingsSortedByStart(t *testing.T) {
	rules := []Rule{
		{ID: "z-outer", Class: "c", Pattern: `abc[0-9]{5}`, MaxMatchLen: 8, Keywords: []string{"abc"}},
		{ID: "a-inner", Class: "c", Pattern: `45`, MaxMatchLen: 2, Keywords: []string{"45"}},
	}
	m, err := NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	findings := m.Find([]byte("abc12345"))
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %+v", findings)
	}
	// z-outer is [0,8], a-inner is [6,8]; canonical order is start-ascending.
	if findings[0].Start != 0 || findings[0].RuleID != "z-outer" {
		t.Fatalf("findings[0] = %+v, want z-outer at start 0", findings[0])
	}
	if findings[1].Start != 6 || findings[1].RuleID != "a-inner" {
		t.Fatalf("findings[1] = %+v, want a-inner at start 6", findings[1])
	}
}

// --- match-group offset resolution ------------------------------------------

// TestScanRuleMatchGroupOffsets pins the capture-group selection + offset math
// in scanRule (the `group < 0 || group*2+1 >= len || indexes[group*2] < 0`
// guard and the `start + indexes[group*2 (+1)]` arithmetic). The black-box
// tests only assert a match count, so the group indexing survived. Here every
// case asserts the exact resolved offsets.
func TestScanRuleMatchGroupOffsets(t *testing.T) {
	cases := []struct {
		name      string
		rule      Rule
		input     string
		wantStart int
		wantEnd   int
	}{
		{
			name:      "group one has distinct start and end",
			rule:      Rule{ID: "g", Class: "c", Pattern: `PRE([0-9]{4})END`, MaxMatchLen: 10, Keywords: []string{"PRE"}, MatchGroup: 1},
			input:     "PRE1234END",
			wantStart: 3, wantEnd: 7,
		},
		{
			name:      "group one starting at window offset zero",
			rule:      Rule{ID: "g", Class: "c", Pattern: `([0-9]{4})END`, MaxMatchLen: 7, Prefilter: "digit", MatchGroup: 1},
			input:     "1234END",
			wantStart: 0, wantEnd: 4,
		},
		{
			name:      "negative group falls back to whole match",
			rule:      Rule{ID: "g", Class: "c", Pattern: `PRE([0-9]{4})END`, MaxMatchLen: 10, Keywords: []string{"PRE"}, MatchGroup: -1},
			input:     "PRE1234END",
			wantStart: 0, wantEnd: 10,
		},
		{
			name:      "out-of-range group falls back to whole match",
			rule:      Rule{ID: "g", Class: "c", Pattern: `PRE([0-9]{4})END`, MaxMatchLen: 10, Keywords: []string{"PRE"}, MatchGroup: 2},
			input:     "PRE1234END",
			wantStart: 0, wantEnd: 10,
		},
		{
			name:      "non-participating optional group falls back to whole match",
			rule:      Rule{ID: "g", Class: "c", Pattern: `([A-Z]+)?[0-9]{4}`, MaxMatchLen: 8, Prefilter: "digit", MatchGroup: 1},
			input:     "1234",
			wantStart: 0, wantEnd: 4,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewMatcher([]Rule{tc.rule})
			if err != nil {
				t.Fatal(err)
			}
			findings := m.Find([]byte(tc.input))
			if len(findings) != 1 {
				t.Fatalf("want exactly one finding, got %+v", findings)
			}
			assertFinding(t, findings, "g", "c", tc.wantStart, tc.wantEnd, 1.0)
		})
	}
}

// TestScanRuleRejectsMatchStartingInLeftContext pins the guard
// `windowStart+indexes[0] < start` in scanRule: the left-context byte carried
// for boundary assertions must never become match content. A digit-prefiltered
// rule whose pattern can extend leftward (`([A-Z]+)?[0-9]{4}`) is the trigger
// shape — without the guard a left-adjacent letter is captured and the finding
// shifts off the digits it was anchored to. Grade the resolved offsets.
func TestScanRuleRejectsMatchStartingInLeftContext(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "g", Class: "c", Pattern: `([A-Z]+)?[0-9]{4}`, MaxMatchLen: 8, Prefilter: "digit", MatchGroup: 0}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		input     string
		wantMatch bool
		wantStart int
		wantEnd   int
	}{
		{"digits at buffer start match", "1234", true, 0, 4},
		{"digits after a non-letter still match", " 1234", true, 1, 5},
		{"left-adjacent letter does not shift the finding", "A1234", false, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := m.Find([]byte(tc.input))
			if !tc.wantMatch {
				if len(findings) != 0 {
					t.Fatalf("input %q: want no finding, got %+v", tc.input, findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("input %q: want one finding, got %+v", tc.input, findings)
			}
			if findings[0].Start != tc.wantStart || findings[0].End != tc.wantEnd {
				t.Fatalf("input %q: want [%d,%d], got [%d,%d]", tc.input, tc.wantStart, tc.wantEnd, findings[0].Start, findings[0].End)
			}
		})
	}
}

// TestScanRuleGuardsInvalidStart pins the `start < 0 || start >= len(text)`
// guard. A negative start must be rejected before the window slice, not indexed
// (mutating `||` to `&&` turns start=-1 into a slice panic).
func TestScanRuleGuardsInvalidStart(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "r", Class: "c", Pattern: `AKIA`, MaxMatchLen: 4, Keywords: []string{"AKIA"}}})
	if err != nil {
		t.Fatal(err)
	}
	text := []byte("AKIA")
	cases := []struct {
		name  string
		start int
	}{
		{"negative start", -1},
		{"start at len", len(text)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := map[candidateKey]struct{}{}
			if got := m.scanRule(text, 0, tc.start, nil, seen); len(got) != 0 {
				t.Fatalf("scanRule(start=%d) = %+v, want no finding", tc.start, got)
			}
		})
	}
}

// --- StreamScan Feed contract ----------------------------------------------

// TestFeedCanResolveNowBoundary pins canResolveNow's
// `start+maxLen+rightContextBytes <= end` boundary directly. The window is
// max_match_len for the value PLUS one right-context byte scanRule needs to
// resolve a trailing boundary (D-26), so a candidate at start 0 with
// max_match_len 8 needs 9 buffered bytes: exact fit at 9 is resolvable, 8 is
// one byte short, 10 is more than enough.
func TestFeedCanResolveNowBoundary(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "d", Class: "c", Pattern: `[0-9]{8}`, MaxMatchLen: 8, Prefilter: "digit"}})
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewStreamScan()
	cases := []struct {
		name  string
		start int
		end   int
		want  bool
	}{
		{"exact window+context fit is resolvable", 0, 9, true},
		{"one byte short is not resolvable", 0, 8, false},
		{"more than enough is resolvable", 0, 10, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.canResolveNow(tc.start, tc.end, 'd'); got != tc.want {
				t.Fatalf("canResolveNow(%d,%d) = %v, want %v", tc.start, tc.end, got, tc.want)
			}
		})
	}
}

// TestFeedUnderSyncedBufferIsSafe pins the `len(reassembled) < absoluteOffset+
// len(chunk)` sync guard. A too-short reassembled buffer must bail cleanly.
// Mutating the `+` to `-` makes the guard pass and the loop index past the
// buffer end (panic).
func TestFeedUnderSyncedBufferIsSafe(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "d", Class: "c", Pattern: `[0-9]{8}`, MaxMatchLen: 8, Prefilter: "digit"}})
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewStreamScan()
	findings, hold := s.Feed([]byte("12345"), []byte("123"))
	if len(findings) != 0 || hold != 0 {
		t.Fatalf("under-synced Feed = (%+v, %d), want (none, 0)", findings, hold)
	}
}

// TestFeedEmptyChunkShortCircuits pins the `s.m == nil` early-return branch
// and the `len(chunk) == 0` branch below it. An empty chunk must not drain
// pending candidates or advance any state, even if a longer reassembled
// buffer is supplied — findings must stay empty. Mutating the nil-matcher
// guard's `==` to `!=` (or removing the empty-chunk branch entirely) would
// let this call fall through into the drain logic and emit early.
//
// holdLen is NOT 0 here: a digit candidate is genuinely still pending after
// the priming "1" byte, and an empty chunk changes nothing about that — see
// TestFeedEmptyChunkPreservesPendingHoldLen for the dedicated regression
// pinning that exact value (a masking-bypass fix: this used to hardcode 0
// unconditionally on any empty chunk, discarding whatever was still pending).
func TestFeedEmptyChunkShortCircuits(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "d", Class: "c", Pattern: `[0-9]{8}`, MaxMatchLen: 8, Prefilter: "digit"}})
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewStreamScan()
	// Prime a pending digit candidate (one digit; window exceeds buffer).
	if f, _ := s.Feed([]byte("1"), []byte("1")); len(f) != 0 {
		t.Fatalf("no finding expected yet, got %+v", f)
	}
	f, _ := s.Feed([]byte{}, []byte("12345678"))
	if len(f) != 0 {
		t.Fatalf("empty chunk Feed emitted findings = %+v, want none (no draining on an empty chunk)", f)
	}
}

// TestFeedEmptyChunkPreservesPendingHoldLen pins the masking-bypass fix: an
// empty-chunk Feed call (the gateway's shape for a no-text control event —
// an SSE keep-alive with no `data:` line, or the OpenAI `[DONE]` sentinel)
// must report the SAME holdLen the prior real-chunk Feed established, not a
// hardcoded 0. Before the fix, any such zero-content event arriving while a
// secret candidate was still mid-window would make the gateway believe
// nothing was pending and flush the already-buffered, unresolved prefix.
func TestFeedEmptyChunkPreservesPendingHoldLen(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "d", Class: "c", Pattern: `[0-9]{8}`, MaxMatchLen: 8, Prefilter: "digit"}})
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewStreamScan()
	// Priming "1" registers a pending digit candidate at start=0; its window
	// (scanWindowLen(8)=9) is nowhere near met by 1 byte, so holdLen = 1
	// (currentEnd 1 - candidateStart 0).
	if _, hold := s.Feed([]byte("1"), []byte("1")); hold != 1 {
		t.Fatalf("holdLen after priming byte = %d, want 1", hold)
	}
	// An empty chunk against a longer reassembled buffer must NOT resolve or
	// drop the candidate (drain logic is only reached past the empty-chunk
	// guard) and must report the SAME holdLen — the candidate is exactly as
	// pending as it was.
	if _, hold := s.Feed([]byte{}, []byte("12345678")); hold != 1 {
		t.Fatalf("holdLen after empty-chunk Feed = %d, want 1 (pending candidate must stay held)", hold)
	}
}

// TestFeedDrainsPendingDigitAtExactFit pins that a digit candidate deferred in
// an earlier chunk is drained and emitted by the Feed that first completes its
// window (value + right-context byte, D-26), not left for Finalize. Kills the
// `len(pending) > 0` negation and the `start+maxLen+rightContextBytes <= end`
// boundary in the drain loop. The trailing non-digit "." is the right-context
// byte scanRule needs; it does not start a second digit candidate.
func TestFeedDrainsPendingDigitAtExactFit(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "d", Class: "c", Pattern: `[0-9]{8}`, MaxMatchLen: 8, Prefilter: "digit"}})
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewStreamScan()
	if f, _ := s.Feed([]byte("12"), []byte("12")); len(f) != 0 {
		t.Fatalf("premature finding: %+v", f)
	}
	f, _ := s.Feed([]byte("345678."), []byte("12345678."))
	assertFinding(t, f, "d", "c", 0, 8, 1.0)
}

// TestFeedDrainsPendingLiteral pins that a literal (AC-anchored) candidate
// deferred in an earlier chunk is drained and emitted by the completing Feed.
// Kills the `len(pendingLiteral) > 0` negation. The trailing " " is the
// right-context byte scanRule needs once the value window is full (D-26).
func TestFeedDrainsPendingLiteral(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "k", Class: "c", Pattern: `AKIA[0-9]{4}`, MaxMatchLen: 8, Keywords: []string{"AKIA"}}})
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewStreamScan()
	if f, _ := s.Feed([]byte("AKIA"), []byte("AKIA")); len(f) != 0 {
		t.Fatalf("premature finding: %+v", f)
	}
	f, _ := s.Feed([]byte("1234 "), []byte("AKIA1234 "))
	assertFinding(t, f, "k", "c", 0, 8, 1.0)
}

// TestFeedKeepsPendingLiteralUntilWindowComplete pins the drain-time window
// check `pc.start + MaxMatchLen <= len(reassembled)` for a pending literal at a
// NON-zero start. A middle chunk that only partially fills the window must
// leave the candidate pending (not scan a truncated window and drop it).
// Mutating the `+` to `-` makes the check pass early, scans an incomplete
// window, finds nothing, drops the candidate, and the secret is lost.
func TestFeedKeepsPendingLiteralUntilWindowComplete(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "k", Class: "c", Pattern: `AKIA[0-9]{4}`, MaxMatchLen: 8, Keywords: []string{"AKIA"}}})
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewStreamScan()
	var got []Finding
	f, _ := s.Feed([]byte("xxAKIA"), []byte("xxAKIA"))
	got = append(got, f...)
	f, _ = s.Feed([]byte("12"), []byte("xxAKIA12"))
	got = append(got, f...)
	f, _ = s.Feed([]byte("34"), []byte("xxAKIA1234"))
	got = append(got, f...)
	got = append(got, s.Finalize([]byte("xxAKIA1234"))...)
	assertFinding(t, got, "k", "c", 2, 10, 1.0)
}

// TestFeedScansLiteralAtExactWindowFit pins the AC-out-time window check
// `start+MaxMatchLen+rightContextBytes <= len(reassembled)`. When the window
// (value + right-context byte, D-26) ends exactly at the buffer end the
// candidate must be scanned in this Feed, not deferred. Mutating `<=` to `<`,
// or dropping the rightContextBytes term, changes this Feed's emission.
func TestFeedScansLiteralAtExactWindowFit(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "k", Class: "c", Pattern: `AKIA[0-9]{4}`, MaxMatchLen: 8, Keywords: []string{"AKIA"}}})
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewStreamScan()
	f, _ := s.Feed([]byte("AKIA1234 "), []byte("AKIA1234 "))
	assertFinding(t, f, "k", "c", 0, 8, 1.0)
}

// TestFeedPromotesDeferredIBANIntoHold pins the deferred-IBAN re-evaluation
// (`len(deferredIBANStarts) > 0`). A lone "G" defers (can't read the next
// byte); the next chunk completing "GB82" must promote it to a pending IBAN
// candidate, which the hold-back length then reflects. Skipping the drain
// leaves hold at 0.
func TestFeedPromotesDeferredIBANIntoHold(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "i", Class: "c", Pattern: `[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}`, MaxMatchLen: 34, Prefilter: "iban"}})
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewStreamScan()
	if _, h1 := s.Feed([]byte("G"), []byte("G")); h1 != 0 {
		t.Fatalf("hold after lone 'G' = %d, want 0", h1)
	}
	_, h2 := s.Feed([]byte("B82"), []byte("GB82"))
	if h2 != 4 {
		t.Fatalf("hold after promoted deferred IBAN = %d, want 4", h2)
	}
}

// TestHoldLenUsesUncertainPrefixLiteral pins the hold arithmetic
// `currentEnd - pc.start` for a pending literal that does NOT start at offset 0.
// The earlier black-box test only exercised start==0, where `-` and `+` agree.
func TestHoldLenUsesUncertainPrefixLiteral(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "k", Class: "c", Pattern: `AKIA[0-9A-Z]{16}`, MaxMatchLen: 20, Keywords: []string{"AKIA"}}})
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewStreamScan()
	// "xxAKIAZ": AKIA anchor completes at start=2; window (20) exceeds the 7-byte
	// buffer, so the whole uncertain prefix [2,7) must be held: 7-2 = 5.
	_, hold := s.Feed([]byte("xxAKIAZ"), []byte("xxAKIAZ"))
	if hold != 5 {
		t.Fatalf("hold with pending literal at start 2 = %d, want 5", hold)
	}
}

// TestHoldLenUsesUncertainPrefixDigit pins the same `currentEnd - pc.start`
// arithmetic for a pending digit candidate at a non-zero start.
func TestHoldLenUsesUncertainPrefixDigit(t *testing.T) {
	m, err := NewMatcher([]Rule{{ID: "d", Class: "c", Pattern: `[0-9]{8}`, MaxMatchLen: 8, Prefilter: "digit"}})
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewStreamScan()
	// "xx4": digit candidate at start=2; window (8) exceeds the 3-byte buffer,
	// so hold is 3-2 = 1.
	_, hold := s.Feed([]byte("xx4"), []byte("xx4"))
	if hold != 1 {
		t.Fatalf("hold with pending digit at start 2 = %d, want 1", hold)
	}
}
