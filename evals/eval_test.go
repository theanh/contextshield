package evals

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theanh/contextshield/engine"
)

func TestEvaluateAllMatch(t *testing.T) {
	rule := engine.Rule{
		ID:          "test-secret",
		Class:       "secret.test",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}
	matcher, err := engine.NewMatcher([]engine.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		entries    []Entry
		wantTP     int
		wantFP     int
		wantFN     int
		wantTN     int
		wantPrec   float64
		wantRecall float64
	}{
		{
			name: "all positives match",
			entries: []Entry{
				{Class: "secret.test", Input: "AKIA1234567890123456", ExpectFinding: true},
			},
			wantTP: 1, wantFP: 0, wantFN: 0, wantTN: 0,
			wantPrec: 1.0, wantRecall: 1.0,
		},
		{
			name: "all negatives rejected",
			entries: []Entry{
				{Class: "secret.test", Input: "AKIA123456789012345", ExpectFinding: false},
			},
			wantTP: 0, wantFP: 0, wantFN: 0, wantTN: 1,
			wantPrec: 1.0, wantRecall: 1.0,
		},
		{
			name: "false positive",
			entries: []Entry{
				{Class: "secret.test", Input: "AKIA1234567890123456", ExpectFinding: false},
			},
			wantTP: 0, wantFP: 1, wantFN: 0, wantTN: 0,
			wantPrec: 0.0, wantRecall: 1.0,
		},
		{
			name: "false negative",
			entries: []Entry{
				{Class: "secret.test", Input: "AKIA1234567890123456", ExpectFinding: true},
				{Class: "secret.test", Input: "clean text", ExpectFinding: false},
			},
			wantTP: 1, wantFP: 0, wantFN: 0, wantTN: 1,
			wantPrec: 1.0, wantRecall: 1.0,
		},
		{
			// An expected finding that does NOT fire increments FN and drags
			// recall below 1.0. Pins the recall denominator (TP+FN, not TP-FN),
			// the FN increment, and the TP-branch conjunction.
			name: "missed expected finding lowers recall",
			entries: []Entry{
				{Class: "secret.test", Input: "AKIA1234567890123456", ExpectFinding: true},
				{Class: "secret.test", Input: "clean text", ExpectFinding: true},
			},
			wantTP: 1, wantFP: 0, wantFN: 1, wantTN: 0,
			wantPrec: 1.0, wantRecall: 0.5,
		},
		{
			name: "mixed precision",
			entries: []Entry{
				{Class: "secret.test", Input: "AKIA1234567890123456", ExpectFinding: true},
				{Class: "secret.test", Input: "AKIA9999999999999999", ExpectFinding: true},
				{Class: "secret.test", Input: "AKIA1234567890123456", ExpectFinding: false},
				{Class: "secret.test", Input: "clean text", ExpectFinding: false},
			},
			wantTP: 2, wantFP: 1, wantFN: 0, wantTN: 1,
			wantPrec: 2.0 / 3.0, wantRecall: 1.0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			corpus := &Corpus{Entries: tc.entries}
			result := Evaluate(matcher, corpus)
			m, ok := result.Metrics["secret.test"]
			if !ok {
				t.Fatalf("missing metrics for secret.test")
			}
			if m.TP != tc.wantTP {
				t.Fatalf("TP = %d, want %d", m.TP, tc.wantTP)
			}
			if m.FP != tc.wantFP {
				t.Fatalf("FP = %d, want %d", m.FP, tc.wantFP)
			}
			if m.FN != tc.wantFN {
				t.Fatalf("FN = %d, want %d", m.FN, tc.wantFN)
			}
			if m.TN != tc.wantTN {
				t.Fatalf("TN = %d, want %d", m.TN, tc.wantTN)
			}
			if m.Precision != tc.wantPrec {
				t.Fatalf("Precision = %v, want %v", m.Precision, tc.wantPrec)
			}
			if m.Recall != tc.wantRecall {
				t.Fatalf("Recall = %v, want %v", m.Recall, tc.wantRecall)
			}
		})
	}
}

func TestEvaluateMultipleClasses(t *testing.T) {
	rules := []engine.Rule{
		{
			ID:          "test-secret",
			Class:       "secret.test",
			Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
			MaxMatchLen: 20,
			Keywords:    []string{"AKIA"},
		},
		{
			ID:          "test-regulated",
			Class:       "regulated.test",
			Pattern:     `\bGB\d{2}[A-Z]{4}\d{14}\b`,
			MaxMatchLen: 22,
			Keywords:    []string{"GB"},
		},
	}
	matcher, err := engine.NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}

	entries := []Entry{
		{Class: "secret.test", Input: "AKIA1234567890123456", ExpectFinding: true},
		{Class: "secret.test", Input: "clean text", ExpectFinding: false},
		{Class: "regulated.test", Input: "GB82WEST12345698765432", ExpectFinding: true},
		{Class: "regulated.test", Input: "clean text", ExpectFinding: false},
	}

	corpus := &Corpus{Entries: entries}
	result := Evaluate(matcher, corpus)

	if len(result.Metrics) != 2 {
		t.Fatalf("expected 2 class metrics, got %d", len(result.Metrics))
	}

	sm := result.Metrics["secret.test"]
	if sm.TP != 1 || sm.FP != 0 || sm.FN != 0 || sm.TN != 1 {
		t.Fatalf("secret.test: TP=%d FP=%d FN=%d TN=%d, want TP=1 FP=0 FN=0 TN=1",
			sm.TP, sm.FP, sm.FN, sm.TN)
	}

	rm := result.Metrics["regulated.test"]
	if rm.TP != 1 || rm.FP != 0 || rm.FN != 0 || rm.TN != 1 {
		t.Fatalf("regulated.test: TP=%d FP=%d FN=%d TN=%d, want TP=1 FP=0 FN=0 TN=1",
			rm.TP, rm.FP, rm.FN, rm.TN)
	}
}

func TestLoadCorpus(t *testing.T) {
	dir := t.TempDir()

	positive := filepath.Join(dir, "secrets.yaml")
	if err := os.WriteFile(positive, []byte("entries:\n  - class: secret.test\n    input: AKIA123\n    expect_finding: true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	negative := filepath.Join(dir, "structural.yaml")
	if err := os.WriteFile(negative, []byte("entries:\n  - class: structural.test\n    input: clean\n    expect_finding: false\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Non-YAML file ignored
	ignored := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(ignored, []byte("not yaml\n"), 0644); err != nil {
		t.Fatal(err)
	}

	corpus, err := LoadCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(corpus.Entries))
	}
}

func TestLoadCorpusEmpty(t *testing.T) {
	dir := t.TempDir()
	corpus, err := LoadCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus.Entries) != 0 {
		t.Fatalf("expected 0 entries in empty dir, got %d", len(corpus.Entries))
	}
}

func TestLoadCorpusBadDir(t *testing.T) {
	_, err := LoadCorpus("/nonexistent/eval/path")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestMeasuredConfidence(t *testing.T) {
	cases := []struct {
		name    string
		metrics *ClassMetrics
		want    float64
	}{
		{
			name:    "clean small sample stays below 1.0",
			metrics: &ClassMetrics{Class: "secret.test", TP: 5, FP: 0, FN: 0, TN: 5},
			want:    0.85, // (5+1)/(5+0+2) = 0.857 — a clean 5-sample corpus is NOT 1.0
		},
		{
			name:    "clean large sample approaches but never reaches 1.0",
			metrics: &ClassMetrics{Class: "secret.test", TP: 1000, FP: 0, FN: 0, TN: 5},
			want:    0.99, // (1001)/(1002) = 0.999
		},
		{
			name:    "no true positives",
			metrics: &ClassMetrics{Class: "secret.test", TP: 0, FP: 0, FN: 5, TN: 0},
			want:    0.5, // (0+1)/(0+0+2)
		},
		{
			name:    "only false positives",
			metrics: &ClassMetrics{Class: "secret.test", TP: 0, FP: 5, FN: 0, TN: 0},
			want:    0.14, // (0+1)/(0+5+2) = 0.142
		},
		{
			name:    "some FPs",
			metrics: &ClassMetrics{Class: "secret.test", TP: 4, FP: 1, FN: 0, TN: 5},
			want:    0.71, // (4+1)/(4+1+2) = 0.714
		},
		{
			name:    "more evidence, one FP",
			metrics: &ClassMetrics{Class: "secret.test", TP: 5, FP: 1, FN: 0, TN: 5},
			want:    0.75, // (5+1)/(5+1+2)
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MeasuredConfidence(tc.metrics)
			if got != tc.want {
				t.Fatalf("MeasuredConfidence = %v, want %v", got, tc.want)
			}
			if got >= 1.0 {
				t.Fatalf("MeasuredConfidence must never reach 1.0 (reserved for deterministic-by-construction), got %v", got)
			}
		})
	}
}

// TestEvaluateCountsCrossClassFalsePositives proves the precision metric sees a
// rule firing the WRONG class on an input — previously invisible because metrics
// were grouped only by the entry's own labeled class.
func TestEvaluateCountsCrossClassFalsePositives(t *testing.T) {
	rules := []engine.Rule{
		{ID: "rule-a", Class: "secret.a", Pattern: `\bAAAA[0-9]{4}\b`, MaxMatchLen: 8, Keywords: []string{"AAAA"}},
		{ID: "rule-b", Class: "secret.b", Pattern: `\bBBBB[0-9]{4}\b`, MaxMatchLen: 8, Keywords: []string{"BBBB"}},
	}
	matcher, err := engine.NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}

	// One entry, labeled secret.a, whose input also trips the secret.b rule.
	// The b match is a false positive for secret.b even though nothing is
	// labeled secret.b.
	result := Evaluate(matcher, &Corpus{Entries: []Entry{
		{Class: "secret.a", Input: "AAAA1111 BBBB2222", ExpectFinding: true},
	}})

	a := result.Metrics["secret.a"]
	if a == nil || a.TP != 1 || a.FP != 0 {
		t.Fatalf("secret.a: want TP=1 FP=0, got %+v", a)
	}
	b := result.Metrics["secret.b"]
	if b == nil {
		t.Fatal("secret.b must appear as a cross-class false positive")
	}
	if b.TP != 0 || b.FP != 1 {
		t.Fatalf("secret.b: want TP=0 FP=1 (cross-class FP), got %+v", b)
	}
}

// TestEvaluateCountsEveryCrossClassFP pins that the cross-class FP loop counts
// EVERY fired non-own class, not just the ones iterated before the own class.
// Mutating the loop's `continue` (skip the own-class TP) to `break` (stop the
// whole loop at the own class) drops the FPs of classes iterated after it.
// Go randomizes map iteration order, so a single entry is a coin flip; the
// repeated corpus makes a dropped FP overwhelmingly likely to surface as a
// short count on at least one entry.
func TestEvaluateCountsEveryCrossClassFP(t *testing.T) {
	rules := []engine.Rule{
		{ID: "rule-own", Class: "secret.own", Pattern: `\bOWNS[0-9]{4}\b`, MaxMatchLen: 8, Keywords: []string{"OWNS"}},
		{ID: "rule-a", Class: "secret.a", Pattern: `\bAAAA[0-9]{4}\b`, MaxMatchLen: 8, Keywords: []string{"AAAA"}},
		{ID: "rule-b", Class: "secret.b", Pattern: `\bBBBB[0-9]{4}\b`, MaxMatchLen: 8, Keywords: []string{"BBBB"}},
	}
	matcher, err := engine.NewMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}

	// Each entry is labeled secret.own (a TP) but also trips secret.a and
	// secret.b (cross-class FPs). Both cross FPs must be counted on every entry.
	e := Entry{Class: "secret.own", Input: "OWNS1111 AAAA2222 BBBB3333", ExpectFinding: true}
	corpus := &Corpus{Entries: []Entry{e, e, e, e, e, e, e, e}}

	result := Evaluate(matcher, corpus)
	if a := result.Metrics["secret.a"]; a == nil || a.FP != 8 {
		t.Fatalf("secret.a: want FP=8 (one per entry), got %+v", a)
	}
	if b := result.Metrics["secret.b"]; b == nil || b.FP != 8 {
		t.Fatalf("secret.b: want FP=8 (one per entry), got %+v", b)
	}
	if own := result.Metrics["secret.own"]; own == nil || own.TP != 8 {
		t.Fatalf("secret.own: want TP=8, got %+v", own)
	}
}

func TestEvaluateDeterministic(t *testing.T) {
	rule := engine.Rule{
		ID:          "test-secret",
		Class:       "secret.test",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}
	matcher, err := engine.NewMatcher([]engine.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}

	entries := []Entry{
		{Class: "secret.test", Input: "AKIA1234567890123456", ExpectFinding: true},
		{Class: "secret.test", Input: "clean text", ExpectFinding: false},
	}
	corpus := &Corpus{Entries: entries}

	first := Evaluate(matcher, corpus)
	second := Evaluate(matcher, corpus)

	m1 := first.Metrics["secret.test"]
	m2 := second.Metrics["secret.test"]
	if m1.TP != m2.TP || m1.FP != m2.FP || m1.FN != m2.FN || m1.TN != m2.TN {
		t.Fatal("eval results not deterministic")
	}
}

func TestReportContainsAllClasses(t *testing.T) {
	result := &Result{
		Metrics: map[string]*ClassMetrics{
			"secret.test":    {Class: "secret.test", TP: 5, FP: 1, FN: 0, TN: 10, Precision: 5.0 / 6.0, Recall: 1.0},
			"regulated.test": {Class: "regulated.test", TP: 3, FP: 0, FN: 0, TN: 5, Precision: 1.0, Recall: 1.0},
		},
	}

	var buf strings.Builder
	RenderReport(&buf, result)
	output := buf.String()

	if !strings.Contains(output, "secret.test") {
		t.Fatal("report missing secret.test")
	}
	if !strings.Contains(output, "regulated.test") {
		t.Fatal("report missing regulated.test")
	}
	if !strings.Contains(output, "83.3%") {
		t.Fatal("report missing precision for secret.test")
	}
}
