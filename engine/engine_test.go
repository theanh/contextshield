package engine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuleYAMLExamples(t *testing.T) {
	for _, rule := range loadFixtureRules(t) {
		rule := rule
		t.Run(rule.ID, func(t *testing.T) {
			if rule.MaxMatchLen <= 0 {
				t.Fatalf("max_match_len is required")
			}
			if len(rule.Examples.Positive) == 0 {
				t.Fatalf("positive examples are required")
			}
			if len(rule.Examples.Negative) == 0 {
				t.Fatalf("negative examples are required")
			}

			matcher, err := NewMatcher([]Rule{rule})
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range rule.Examples.Positive {
				findings := matcher.Find([]byte(input))
				if len(findings) == 0 {
					t.Fatalf("positive example did not match")
				}
				for _, finding := range findings {
					if finding.RuleID != rule.ID {
						t.Fatalf("expected rule %q, got %q", rule.ID, finding.RuleID)
					}
					if finding.Start < 0 || finding.End > len(input) || finding.Start >= finding.End {
						t.Fatalf("invalid offsets: %+v for input length %d", finding, len(input))
					}
				}
			}
			for _, input := range rule.Examples.Negative {
				if findings := matcher.Find([]byte(input)); len(findings) != 0 {
					t.Fatalf("negative example matched unexpectedly: %+v", findings)
				}
			}
		})
	}
}

func TestFindsOffsetsAndConfidence(t *testing.T) {
	rules := loadFixtureRules(t)
	matcher, err := NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}

	secret := "AKIA" + strings.Repeat("A", 16)
	text := []byte("prefix " + secret + " and structural id 123-45-6789")
	findings := matcher.Find(text)

	assertFinding(t, findings, "aws-access-key-id", "secret.aws_access_key", 7, 27, 1.0)
	assertFinding(t, findings, "us-ssn-structural", "structural.ssn", bytes.Index(text, []byte("123-45-6789")), bytes.Index(text, []byte("123-45-6789"))+11, 0.85)
}

// TestStructuralRulesAreConfidenceGated guards Invariant 7 / D-18: structural
// classes (no checksum, never deterministic-by-construction) must carry a gated
// confidence in (0,1), never 1.0 — otherwise a match clears every min_confidence
// gate and can auto-block a random 9-digit ID formatted like an SSN.
func TestStructuralRulesAreConfidenceGated(t *testing.T) {
	for _, rule := range loadFixtureRules(t) {
		if !strings.HasPrefix(rule.Class, "structural.") {
			continue
		}
		if rule.Confidence <= 0 || rule.Confidence >= 1.0 {
			t.Fatalf("structural rule %q confidence = %v, want (0,1) — 1.0 is reserved for deterministic-by-construction detection", rule.ID, rule.Confidence)
		}
	}
}

func TestDeterministicValidatorsRejectLookalikes(t *testing.T) {
	rules := loadFixtureRules(t)
	matcher, err := NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}

	cases := []string{
		"timestamp 1730000000001",
		"bad card 4111 1111 1111 1112",
		"bad iban GB00 WEST 1234 5698 7654 32",
		"bad ssn 987-65-4321",
		"low entropy api_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	for _, input := range cases {
		if findings := matcher.Find([]byte(input)); len(findings) != 0 {
			t.Fatalf("lookalike matched unexpectedly for %q: %+v", input, findings)
		}
	}
}

func TestLiteralPrefilterIsCaseTolerantButRegexStillRules(t *testing.T) {
	rule := Rule{
		ID:          "generic-high-entropy-secret",
		Class:       "secret.generic",
		Pattern:     `(?i)(?:api[_-]?key|secret|token)["']?\s*[:=]\s*["']?([A-Za-z0-9_=-]{32,})`,
		MaxMatchLen: 96,
		Keywords:    []string{"api_key"},
		Validators:  []string{"entropy"},
		Confidence:  0.75,
		MatchGroup:  1,
	}
	matcher, err := NewMatcher([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}

	findings := matcher.Find([]byte("API_KEY=Qa7xP2mN9vL4sT8rY1uI6oE3wA5dF0gH"))
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}

	aws := Rule{
		ID:          "aws-access-key-id",
		Class:       "secret.aws_access_key",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}
	matcher, err = NewMatcher([]Rule{aws})
	if err != nil {
		t.Fatal(err)
	}
	if findings := matcher.Find([]byte("akia" + strings.Repeat("a", 16))); len(findings) != 0 {
		t.Fatalf("case-sensitive regex should reject lowercase key: %+v", findings)
	}
}

// TestLiteralPrefilterWordBoundaries pins the candidate-window boundary fix
// for literal/keyword-prefiltered rules (Aho-Corasick has no token-boundary
// notion, so unlike the digit/IBAN prefilters it registers a candidate for a
// keyword occurring anywhere, including inside a longer word). A rule whose
// regex uses \b at both ends must resolve those boundaries against the real
// neighbor bytes, not the candidate-window edge:
//   - left:  a keyword embedded mid-word ("M"+key) is NOT a boundary, so no match;
//   - right: an over-length token (key + one extra body char, where the value
//     is already at max_match_len) is NOT a clean token end, so no match.
// Two distinct literal rules (AKIA and a synthetic TOKENX) prove this is a
// property of the literal-prefilter path in general, not an AKIA-specific patch.
func TestLiteralPrefilterWordBoundaries(t *testing.T) {
	rules := []Rule{
		{ID: "aws-access-key-id", Class: "secret.aws_access_key", Pattern: `\bAKIA[0-9A-Z]{16}\b`, MaxMatchLen: 20, Keywords: []string{"AKIA"}},
		{ID: "sample-token", Class: "secret.sample", Pattern: `\bTOKENX[0-9A-Z]{6}\b`, MaxMatchLen: 12, Keywords: []string{"TOKENX"}},
	}
	matcher, err := NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		input      string
		wantRuleID string // "" means: expect no finding
	}{
		{"akia standalone", "AKIAIOSFODNN7EXAMPLE", "aws-access-key-id"},
		{"akia after non-word byte", "key AKIAIOSFODNN7EXAMPLE", "aws-access-key-id"},
		{"akia mid-word left boundary", "MAKIAVELLIAN0POLITICS", ""},
		{"akia over-length right boundary", "AKIA" + strings.Repeat("A", 17), ""},
		{"token standalone", "TOKENX1A2B3C", "sample-token"},
		{"token after non-word byte", "use TOKENX1A2B3C now", "sample-token"},
		{"token mid-word left boundary", "XTOKENX1A2B3C", ""},
		{"token over-length right boundary", "TOKENX1A2B3C4", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := matcher.Find([]byte(tc.input))
			if tc.wantRuleID == "" {
				if len(findings) != 0 {
					t.Fatalf("input %q: want no finding, got %+v", tc.input, findings)
				}
				return
			}
			if len(findings) != 1 || findings[0].RuleID != tc.wantRuleID {
				t.Fatalf("input %q: want exactly one %q finding, got %+v", tc.input, tc.wantRuleID, findings)
			}
		})
	}
}

// TestPANPatternDoesNotConsumeTrailingSeparator pins a fix to
// credit-card-pan.yaml's pattern: the old shape `(?:\d[ -]?){13,19}` put the
// optional separator AFTER each digit, so when a PAN was immediately followed
// by a bare space/dash and then non-digit text, the greedy regex swallowed
// that trailing separator into the match (e.g. "1111 please" -> match ends
// after the space, masking would glue "****please" together, corrupting
// adjacent legitimate content). The fixed shape `\d(?:[ -]?\d){12,18}` puts
// the separator BEFORE each subsequent digit, so every match ends on a
// mandatory digit — a trailing separator can never be captured. This mirrors
// why iban.yaml's `(?: ?[A-Z0-9]){10,32}` was never affected: same principle,
// separator-before-character. Uses the real production rule file so a
// regression in the shipped pattern (not a copy) is caught.
func TestPANPatternDoesNotConsumeTrailingSeparator(t *testing.T) {
	rules := loadFixtureRules(t)
	matcher, err := NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		input     string
		wantStart int
		wantEnd   int
	}{
		{"space before trailing word not consumed", "my card is 4111 1111 1111 1111 please charge it", 11, 30},
		{"period after PAN not consumed (regression baseline)", "card: 4111 1111 1111 1111.", 6, 25},
		{"dash before trailing word not consumed", "card 4111 1111 1111 1111-ish", 5, 24},
		{"PAN at end of string still matches fully", "4111 1111 1111 1111", 0, 19},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := matcher.Find([]byte(tc.input))
			if len(findings) != 1 {
				t.Fatalf("input %q: want exactly one finding, got %+v", tc.input, findings)
			}
			if findings[0].Start != tc.wantStart || findings[0].End != tc.wantEnd {
				t.Fatalf("input %q: span = [%d:%d] %q, want [%d:%d] %q",
					tc.input, findings[0].Start, findings[0].End, tc.input[findings[0].Start:findings[0].End],
					tc.wantStart, tc.wantEnd, tc.input[tc.wantStart:tc.wantEnd])
			}
		})
	}
}

// TestRuleMatchesDoNotConsumeTrailingSeparator is the general form of the
// defect TestPANPatternDoesNotConsumeTrailingSeparator pins for one specific
// rule: for every production rule's own declared positive example, appending
// a separator + word character (" x") must not extend that rule's match past
// its original end offset. A future rule (including a community-contributed
// one, per D-12) written with the same "(?:X[sep]?){n,m}" shape — separator
// AFTER each character, so a trailing separator can be greedily swallowed
// when followed by non-matching content — is caught here automatically using
// only the rule's own example, without a dedicated per-rule regression test.
func TestRuleMatchesDoNotConsumeTrailingSeparator(t *testing.T) {
	for _, rule := range loadFixtureRules(t) {
		rule := rule
		t.Run(rule.ID, func(t *testing.T) {
			matcher, err := NewMatcher([]Rule{rule})
			if err != nil {
				t.Fatal(err)
			}
			for _, example := range rule.Examples.Positive {
				base := matcher.Find([]byte(example))
				if len(base) == 0 {
					continue // standalone match failure is TestRuleYAMLExamples' concern, not this property
				}
				baseEnd := base[0].End

				extended := example + " x"
				got := matcher.Find([]byte(extended))
				if len(got) == 0 {
					continue // extension broke the match for a reason unrelated to this property
				}
				if got[0].End > baseEnd {
					t.Fatalf("rule %q: appending a trailing separator extended the match past its own value — end went from %d to %d on %q (extended match consumed %q)",
						rule.ID, baseEnd, got[0].End, example, extended[baseEnd:got[0].End])
				}
			}
		})
	}
}

func TestRequiresMaxMatchLen(t *testing.T) {
	_, err := NewMatcher([]Rule{{
		ID:       "missing-bound",
		Class:    "secret.test",
		Pattern:  `test`,
		Keywords: []string{"test"},
	}})
	if err == nil {
		t.Fatal("expected missing max_match_len to fail")
	}
	if !strings.Contains(err.Error(), "max_match_len") {
		t.Fatalf("expected max_match_len error, got %q", err.Error())
	}
}

func TestRegexOnlySeesBoundedCandidateWindow(t *testing.T) {
	rule := Rule{
		ID:          "bounded",
		Class:       "secret.test",
		Pattern:     `anchor.{12}target`,
		MaxMatchLen: 12,
		Keywords:    []string{"anchor"},
	}
	matcher, err := NewMatcher([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if findings := matcher.Find([]byte("anchor123456789012target")); len(findings) != 0 {
		t.Fatalf("regex should not see past max_match_len window: %+v", findings)
	}
}

func BenchmarkRepresentativeCorpus(b *testing.B) {
	rules := loadFixtureRules(b)
	matcher, err := NewMatcher(rules)
	if err != nil {
		b.Fatal(err)
	}
	corpus := representativeCorpus()
	b.SetBytes(int64(len(corpus)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matcher.Find(corpus)
	}
}

func BenchmarkThousandRulesNoMatch(b *testing.B) {
	benchmarkNoMatchRules(b, 1000)
}

func BenchmarkSingleRuleNoMatch(b *testing.B) {
	benchmarkNoMatchRules(b, 1)
}

func benchmarkNoMatchRules(b *testing.B, ruleCount int) {
	rules := make([]Rule, 0, 1000)
	for i := 0; i < ruleCount; i++ {
		keyword := fmt.Sprintf("never-present-anchor-%04d", i)
		rules = append(rules, Rule{
			ID:          fmt.Sprintf("synthetic-%04d", i),
			Class:       "secret.synthetic",
			Pattern:     regexpQuote(keyword) + `[A-Z0-9]{4}`,
			MaxMatchLen: len(keyword) + 4,
			Keywords:    []string{keyword},
		})
	}
	matcher, err := NewMatcher(rules)
	if err != nil {
		b.Fatal(err)
	}
	corpus := bytes.Repeat([]byte("ordinary model payload without matching anchors\n"), 1<<14)
	b.SetBytes(int64(len(corpus)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matcher.Find(corpus)
	}
}

func loadFixtureRules(tb testing.TB) []Rule {
	tb.Helper()
	paths := []string{
		"../rules/secrets/aws-access-key-id.yaml",
		"../rules/secrets/generic-high-entropy.yaml",
		"../rules/regulated/credit-card-pan.yaml",
		"../rules/regulated/iban.yaml",
		"../rules/structural/ssn.yaml",
	}
	rules := make([]Rule, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			tb.Fatal(err)
		}
		rule, err := ParseRuleYAML(data)
		if err != nil {
			tb.Fatal(err)
		}
		rules = append(rules, rule)
	}
	return rules
}

func assertFinding(t *testing.T, findings []Finding, ruleID, class string, start, end int, confidence float64) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			if finding.Class != class {
				t.Fatalf("expected class %q, got %q", class, finding.Class)
			}
			if finding.Start != start || finding.End != end {
				t.Fatalf("expected offsets %d-%d, got %d-%d", start, end, finding.Start, finding.End)
			}
			if finding.Confidence != confidence {
				t.Fatalf("expected confidence %.2f, got %.2f", confidence, finding.Confidence)
			}
			return
		}
	}
	t.Fatalf("missing finding for rule %q in %+v", ruleID, findings)
}

// TestStreamingFeedEquivalence feeds a known corpus through StreamScan one
// byte at a time and asserts the merged findings equal what Find returns over
// the whole text. Grade the outcome (same findings), not the call sequence.
func TestStreamingFeedEquivalence(t *testing.T) {
	rules := loadFixtureRules(t)
	matcher, err := NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	text := representativeCorpus()
	want := matcher.Find(text)

	scanner := matcher.NewStreamScan()
	var got []Finding
	for i := 0; i < len(text); i++ {
		f, _ := scanner.Feed(text[i:i+1], text[:i+1])
		got = append(got, f...)
	}
	got = append(got, scanner.Finalize(text)...)
	if len(got) != len(want) {
		t.Fatalf("streaming findings count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("streaming[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestStreamingFeedEquivalenceChunked runs the same equivalence with larger,
// realistic chunk sizes (1, 8, 256, 1024) to catch off-by-ones that hide when
// chunk size == 1.
func TestStreamingFeedEquivalenceChunked(t *testing.T) {
	rules := loadFixtureRules(t)
	matcher, err := NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	text := representativeCorpus()
	want := matcher.Find(text)
	for _, chunkSize := range []int{1, 8, 256, 1024, len(text)} {
		scanner := matcher.NewStreamScan()
		var got []Finding
		for i := 0; i < len(text); i += chunkSize {
			end := i + chunkSize
			if end > len(text) {
				end = len(text)
			}
			f, _ := scanner.Feed(text[i:end], text[:end])
			got = append(got, f...)
		}
		got = append(got, scanner.Finalize(text)...)
		if len(got) != len(want) {
			t.Fatalf("chunk=%d: streaming findings count = %d, want %d", chunkSize, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("chunk=%d: streaming[%d] = %+v, want %+v", chunkSize, i, got[i], want[i])
			}
		}
	}
}

// TestStreamingHoldLenZeroOnProse asserts the D-16 promise: at the root
// automaton state (no live keyword partial), holdLen is 0. This is what
// makes p50 TTFT overhead ~0 on typical prose streams.
func TestStreamingHoldLenZeroOnProse(t *testing.T) {
	rule := Rule{
		ID:          "aws-access-key-id",
		Class:       "secret.aws_access_key",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}
	matcher, err := NewMatcher([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	scanner := matcher.NewStreamScan()
	prose := []byte("the quick brown fox jumps over the lazy dog and more ordinary prose here")
	_, hold := scanner.Feed(prose, prose)
	if hold != 0 {
		t.Fatalf("holdLen on prose with no live anchor = %d, want 0", hold)
	}
}

// TestStreamingHoldLenGrowsInsideAnchor asserts holdLen tracks the live
// automaton depth: feeding "AKI" (3 bytes of the 4-byte AKIA anchor) leaves
// hold=3, not max_match_len=20. This is the specific D-16 implementation
// contract — the rejected fixed-window approach would have returned 20.
func TestStreamingHoldLenGrowsInsideAnchor(t *testing.T) {
	rule := Rule{
		ID:          "aws-access-key-id",
		Class:       "secret.aws_access_key",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}
	matcher, err := NewMatcher([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	scanner := matcher.NewStreamScan()
	// "AK" -> state at depth 2; hold must be 2, not 20.
	text := []byte("AK")
	_, hold := scanner.Feed(text, text)
	if hold != 2 {
		t.Fatalf("holdLen after \"AK\" = %d, want 2", hold)
	}
	// Extend to "AKI" -> depth 3.
	text = []byte("AKI")
	scanner = matcher.NewStreamScan()
	_, hold = scanner.Feed(text, text)
	if hold != 3 {
		t.Fatalf("holdLen after \"AKI\" = %d, want 3", hold)
	}
	// "AKIAX" — anchor completed at position 4 ("AKIA"), then "X". The AC
	// has no live keyword prefix at this state (X doesn't extend any
	// keyword), but the literal candidate at start=0 has its max_match_len
	// regex window (=20) extending past chunk end (=5), so it is pending in
	// pendingLiteral. hold must cover the uncertain buffered prefix — from the
	// candidate start (0) to the current end (5), i.e. all 5 bytes — so the
	// gateway holds "AKIAX" rather than flushing the prefix of a possible
	// secret. Holding only the unmet tail (20-5=15) would still clamp safeEnd
	// to 0 here, but once >half the window has arrived that formula under-holds
	// and leaks the buffered prefix; currentEnd-start is the correct measure.
	text = []byte("AKIAX")
	scanner = matcher.NewStreamScan()
	_, hold = scanner.Feed(text, text)
	if hold != 5 { // currentEnd(5) - candidateStart(0)
		t.Fatalf("holdLen after \"AKIAX\" = %d, want 5 (uncertain buffered prefix)", hold)
	}
}

// TestStreamingHoldLenPreservedAcrossEmptyChunkFeed pins a fix: Feed's
// zero-length-chunk fast path used to unconditionally return holdLen=0,
// discarding whatever pending state (an in-flight literal candidate, an
// automaton partial match) was already live from an earlier Feed call. A
// gateway that calls Feed once per SSE event — including no-text control
// events like an SSE keep-alive or the OpenAI [DONE] sentinel, which decode
// to zero new bytes — would see holdLen collapse to 0 the moment such an
// event arrived, flushing an already-buffered, not-yet-resolved secret
// prefix to the client. Feed(nil, ...) with a genuinely pending candidate
// must report the SAME holdLen the prior real-chunk Feed reported, not 0.
func TestStreamingHoldLenPreservedAcrossEmptyChunkFeed(t *testing.T) {
	rule := Rule{
		ID:          "aws-access-key-id",
		Class:       "secret.aws_access_key",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}
	matcher, err := NewMatcher([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	scanner := matcher.NewStreamScan()
	text := []byte("AKIAX")
	_, hold1 := scanner.Feed(text, text)
	if hold1 != 5 {
		t.Fatalf("holdLen after \"AKIAX\" = %d, want 5", hold1)
	}
	// A zero-length chunk (the gateway's shape for a no-text control event)
	// against the SAME reassembled buffer: the pending literal candidate at
	// start=0 is exactly as pending as it was — holdLen must still be 5,
	// not 0.
	_, hold2 := scanner.Feed(nil, text)
	if hold2 != 5 {
		t.Fatalf("holdLen after empty-chunk Feed = %d, want 5 (pending candidate must stay held)", hold2)
	}
}

// TestStreamingDigitCrossChunkMatch asserts that a digit-prefilter rule
// (PAN) detects a card number split across two chunks. The candidate
// window crosses the boundary; the next Feed resolves it.
func TestStreamingDigitCrossChunkMatch(t *testing.T) {
	card := "4111 1111 1111 1111"
	half := len(card) / 2
	chunk1 := []byte("card: " + card[:half])
	chunk2 := []byte(card[half:] + " done")
	text := append([]byte{}, chunk1...)
	text = append(text, chunk2...)
	rules := loadFixtureRules(t)
	matcher, err := NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	want := matcher.Find(text)
	if len(want) == 0 {
		t.Fatal("expected PAN finding over full text")
	}
	scanner := matcher.NewStreamScan()
	var got []Finding
	f, _ := scanner.Feed(chunk1, chunk1)
	got = append(got, f...)
	f, _ = scanner.Feed(chunk2, text)
	got = append(got, f...)
	got = append(got, scanner.Finalize(text)...)
	// Dedup across chunk boundaries may double-count in edge cases; the
	// outcome invariant is that the PAN finding is present with the same
	// offsets as the non-streaming Find.
	found := false
	for _, g := range got {
		for _, w := range want {
			if g == w {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("streaming did not produce a PAN finding matching Find: got %+v, want %+v", got, want)
	}
}

// TestStreamingHoldLenDigitsInFlight asserts that a digit candidate whose
// max_match_len window extends past the chunk boundary produces a non-zero
// hold, so the gateway knows to defer the boundary bytes.
func TestStreamingHoldLenDigitsInFlight(t *testing.T) {
	rules := loadFixtureRules(t)
	matcher, err := NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	scanner := matcher.NewStreamScan()
	// Feed only the first digit of a PAN candidate; window (max 38) extends
	// well past chunk end.
	chunk := []byte("card 4")
	_, hold := scanner.Feed(chunk, chunk)
	if hold <= 0 {
		t.Fatalf("holdLen with in-flight digit candidate = %d, want > 0", hold)
	}
}

func representativeCorpus() []byte {
	base := []byte(strings.Repeat("retrieved chunk prose with ordinary JSON fields and no matching anchors. ", 256))
	examples := [][]byte{
		[]byte("billing card 4111 1111 1111 1111 "),
		[]byte("iban GB82 WEST 1234 5698 7654 32 "),
		[]byte("identifier 123-45-6789 "),
	}
	return bytes.Join(append([][]byte{base}, examples...), nil)
}

func regexpQuote(text string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`.`, `\.`,
		`+`, `\+`,
		`*`, `\*`,
		`?`, `\?`,
		`(`, `\(`,
		`)`, `\)`,
		`[`, `\[`,
		`]`, `\]`,
		`{`, `\{`,
		`}`, `\}`,
		`^`, `\^`,
		`$`, `\$`,
		`|`, `\|`,
	)
	return replacer.Replace(text)
}
