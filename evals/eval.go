package evals

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/theanh/contextshield/engine"
	"gopkg.in/yaml.v3"
)

type Entry struct {
	RuleID        string `yaml:"rule_id"`
	Class         string `yaml:"class"`
	Input         string `yaml:"input"`
	ExpectFinding bool   `yaml:"expect_finding"`
	Description   string `yaml:"description,omitempty"`
}

type Corpus struct {
	Entries []Entry `yaml:"entries"`
}

type ClassMetrics struct {
	Class          string
	TP, FP, FN, TN int
	Precision      float64
	Recall         float64
}

func (m *ClassMetrics) compute() {
	if predicted := m.TP + m.FP; predicted > 0 {
		m.Precision = float64(m.TP) / float64(predicted)
	} else {
		m.Precision = 1.0 // no predictions → vacuously precise
	}
	if actual := m.TP + m.FN; actual > 0 {
		m.Recall = float64(m.TP) / float64(actual)
	} else {
		m.Recall = 1.0 // no positives to find → vacuously complete
	}
}

func LoadCorpus(dir string) (*Corpus, error) {
	var all []Entry
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read corpus %s: %w", path, err)
		}
		var c Corpus
		if err := yaml.Unmarshal(data, &c); err != nil {
			return fmt.Errorf("parse corpus %s: %w", path, err)
		}
		all = append(all, c.Entries...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Corpus{Entries: all}, nil
}

type Result struct {
	Metrics map[string]*ClassMetrics
}

// Evaluate scores the corpus per class. A finding of class F on an entry is a
// true positive for F only when the entry expected F (ExpectFinding &&
// entry.Class == F). Every other finding is a false positive for its OWN class,
// including cross-class matches — a rule firing class Y on an input labeled X
// counts as an FP for Y. Without that, a rule that over-triggers on other
// classes' inputs keeps a clean precision score and the published numbers lie.
func Evaluate(matcher *engine.Matcher, corpus *Corpus) *Result {
	metrics := make(map[string]*ClassMetrics)
	metricFor := func(class string) *ClassMetrics {
		m, ok := metrics[class]
		if !ok {
			m = &ClassMetrics{Class: class}
			metrics[class] = m
		}
		return m
	}

	for _, entry := range corpus.Entries {
		fired := make(map[string]bool)
		for _, f := range matcher.Find([]byte(entry.Input)) {
			fired[f.Class] = true
		}

		// The entry's own labeled class: TP / FN / TN.
		own := metricFor(entry.Class)
		switch {
		case entry.ExpectFinding && fired[entry.Class]:
			own.TP++
		case entry.ExpectFinding:
			own.FN++
		case !fired[entry.Class]:
			own.TN++
		}

		// Every fired class that isn't this entry's expected true positive is a
		// false positive for that class (same-class negatives AND cross-class
		// spurious matches).
		for cls := range fired {
			if entry.ExpectFinding && cls == entry.Class {
				continue
			}
			metricFor(cls).FP++
		}
	}

	for _, m := range metrics {
		m.compute()
	}
	return &Result{Metrics: metrics}
}

// MeasuredConfidence is a Laplace-smoothed (add-one) precision estimate from the
// eval corpus, truncated to two decimals. It never returns 1.0: a finite corpus
// can measure precision but cannot PROVE determinism, and confidence 1.0 is
// reserved for deterministic-by-construction detection (Invariant 7 / D-18).
// Add-one smoothing also downweights tiny samples (5 clean hits → 0.85, not 1.0).
// Use it to inform a rule's policy min_confidence gate, never to overwrite the
// rule's intrinsic construction-band confidence.
func MeasuredConfidence(metrics *ClassMetrics) float64 {
	est := float64(metrics.TP+1) / float64(metrics.TP+metrics.FP+2)
	return math.Floor(est*100) / 100
}
