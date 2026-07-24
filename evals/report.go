package evals

import (
	"fmt"
	"io"
	"math"
	"sort"
)

const header = `========================================
ContextShield — Eval Report
Measured per-class precision/recall
========================================

`

func RenderReport(w io.Writer, result *Result) {
	io.WriteString(w, header)

	classes := make([]string, 0, len(result.Metrics))
	for class := range result.Metrics {
		classes = append(classes, class)
	}
	sort.Strings(classes)

	fmt.Fprintf(w, "%-36s %7s %7s %5s %5s %5s %5s %8s\n",
		"Class", "Prec", "Recall", "TP", "FP", "FN", "TN", "Confidence")
	fmt.Fprintf(w, "%-36s %7s %7s %5s %5s %5s %5s %8s\n",
		"-----", "----", "------", "--", "--", "--", "--", "----------")

	for _, class := range classes {
		m := result.Metrics[class]
		prec := formatPct(m.Precision)
		recall := formatPct(m.Recall)
		conf := MeasuredConfidence(m)
		fmt.Fprintf(w, "%-36s %7s %7s %5d %5d %5d %5d %8.2f\n",
			class, prec, recall, m.TP, m.FP, m.FN, m.TN, conf)
	}
}

func formatPct(v float64) string {
	if math.IsNaN(v) {
		return "  N/A"
	}
	return fmt.Sprintf("%5.1f%%", v*100)
}

const footer = `
NOTE: These are measured eval-corpus numbers against curated positive and
negative cases. Published precision/recall may differ on real traffic.
Confidence values are set from measured FP rates per D-14.
`

func RenderReportWithThresholds(w io.Writer, result *Result) {
	RenderReport(w, result)
	io.WriteString(w, footer)
}
