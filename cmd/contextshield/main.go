package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/theanh/contextshield/engine"
	"github.com/theanh/contextshield/evals"
	"github.com/theanh/contextshield/gate"
	"github.com/theanh/contextshield/ledger"
	"github.com/theanh/contextshield/policy"
	"github.com/theanh/contextshield/scan"
)

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit code %d", e) }

const (
	exitError    exitCode = 2
	exitFindings exitCode = 1
)

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		var code exitCode
		if errors.As(err, &code) {
			os.Exit(int(code))
		}
		log.Fatal(err)
	}
}

type command struct {
	name  string
	serve serveOptions
	scan  scanOptions
	eval  evalOptions
}

type serveOptions struct {
	configPath string
}

type scanOptions struct {
	rulesDir string
	json     bool
	paths    []string
}

type evalOptions struct {
	mode         string // "run" or "render"
	rulesDir     string
	corpusDir    string
	minPrecision float64
	minRecall    float64
}

func run(args []string, output io.Writer) error {
	cmd, err := parseCommand(args, output)
	if err != nil {
		return err
	}

	switch cmd.name {
	case "help":
		return nil
	case "serve":
		return serve(cmd.serve)
	case "scan":
		return runScan(cmd.scan)
	case "eval":
		return runEval(cmd.eval)
	default:
		return fmt.Errorf("unknown command %q", cmd.name)
	}
}

func parseCommand(args []string, output io.Writer) (command, error) {
	if len(args) == 0 {
		return parseServeCommand(nil, output)
	}

	switch args[0] {
	case "serve":
		return parseServeCommand(args[1:], output)
	case "scan":
		return parseScanCommand(args[1:], output)
	case "eval":
		return parseEvalCommand(args[1:], output)
	case "help", "-h", "--help":
		printUsage(output)
		return command{name: "help"}, nil
	default:
		if strings.HasPrefix(args[0], "-") {
			return parseServeCommand(args, output)
		}
		printUsage(output)
		return command{}, fmt.Errorf("unknown command %q", args[0])
	}
}

func parseServeCommand(args []string, output io.Writer) (command, error) {
	opts := serveOptions{configPath: "shield.yaml"}
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&opts.configPath, "config", opts.configPath, "path to shield.yaml")
	flags.Usage = func() {
		printUsage(output)
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return command{name: "help"}, nil
		}
		return command{}, err
	}
	if flags.NArg() > 0 {
		printUsage(output)
		return command{}, fmt.Errorf("serve: unexpected argument %q", flags.Arg(0))
	}
	return command{name: "serve", serve: opts}, nil
}

func parseScanCommand(args []string, output io.Writer) (command, error) {
	opts := scanOptions{rulesDir: "rules"}
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&opts.rulesDir, "rules", opts.rulesDir, "path to rules directory")
	flags.BoolVar(&opts.json, "json", false, "output findings as JSON")
	flags.Usage = func() {
		fmt.Fprintf(output, "Usage: contextshield scan [flags] [path ...]\n\n")
		fmt.Fprintf(output, "Scan files and directories for secrets and regulated data.\n")
		fmt.Fprintf(output, "Exit codes: 0=clean, 1=findings, 2=error\n\n")
		fmt.Fprintf(output, "Flags:\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return command{name: "help"}, nil
		}
		return command{}, err
	}
	opts.paths = flags.Args()
	if len(opts.paths) == 0 {
		opts.paths = []string{"."}
	}
	return command{name: "scan", scan: opts}, nil
}

func printEvalUsage(output io.Writer) {
	fmt.Fprintf(output, "Usage: contextshield eval run [flags]\n")
	fmt.Fprintf(output, "       contextshield eval render [flags]\n\n")
	fmt.Fprintf(output, "Run or render the eval corpus through the detection engine.\n")
	fmt.Fprintf(output, "'run' exits non-zero if any class falls below threshold (CI gate).\n")
	fmt.Fprintf(output, "'render' prints the publishable per-class precision/recall report.\n\n")
	fmt.Fprintf(output, "Flags:\n")
	fmt.Fprintf(output, "  -rules string    path to rules directory (default \"rules\")\n")
	fmt.Fprintf(output, "  -corpus string   path to eval corpus directory (default \"evals/corpus\")\n")
	fmt.Fprintf(output, "  -min-precision   minimum precision threshold for CI gate (default 0.8)\n")
	fmt.Fprintf(output, "  -min-recall      minimum recall threshold for CI gate (default 0.8)\n")
}

func parseEvalCommand(args []string, output io.Writer) (command, error) {
	if len(args) == 0 {
		printEvalUsage(output)
		return command{}, fmt.Errorf("eval requires a subcommand: run or render")
	}
	sub := args[0]
	rest := args[1:]

	opts := evalOptions{
		mode:         sub,
		rulesDir:     "rules",
		corpusDir:    "evals/corpus",
		minPrecision: 0.80,
		minRecall:    0.80,
	}

	flags := flag.NewFlagSet("eval "+sub, flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&opts.rulesDir, "rules", opts.rulesDir, "path to rules directory")
	flags.StringVar(&opts.corpusDir, "corpus", opts.corpusDir, "path to eval corpus directory")
	flags.Float64Var(&opts.minPrecision, "min-precision", opts.minPrecision, "minimum precision threshold for CI gate")
	flags.Float64Var(&opts.minRecall, "min-recall", opts.minRecall, "minimum recall threshold for CI gate")
	flags.Usage = func() {
		printEvalUsage(output)
	}
	if err := flags.Parse(rest); err != nil {
		if err == flag.ErrHelp {
			return command{name: "help"}, nil
		}
		return command{}, err
	}
	if flags.NArg() > 0 {
		printEvalUsage(output)
		return command{}, fmt.Errorf("eval %s: unexpected argument %q", sub, flags.Arg(0))
	}

	switch sub {
	case "run", "render":
	case "-h", "--help", "help":
		printEvalUsage(output)
		return command{name: "help"}, nil
	default:
		printEvalUsage(output)
		return command{}, fmt.Errorf("eval: unknown subcommand %q (expected run or render)", sub)
	}

	return command{name: "eval", eval: opts}, nil
}

func runEval(opts evalOptions) error {
	matcher, err := loadRules(opts.rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading rules from %s: %v\n", opts.rulesDir, err)
		return exitError
	}

	corpus, err := evals.LoadCorpus(opts.corpusDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading corpus from %s: %v\n", opts.corpusDir, err)
		return exitError
	}

	if len(corpus.Entries) == 0 {
		fmt.Fprintf(os.Stderr, "error: no entries found in corpus %s\n", opts.corpusDir)
		return exitError
	}

	result := evals.Evaluate(matcher, corpus)

	switch opts.mode {
	case "render":
		evals.RenderReportWithThresholds(os.Stdout, result)
		return nil
	case "run":
		evals.RenderReport(os.Stdout, result)

		if uncovered := uncoveredRuleClasses(matcher.Rules(), corpus); len(uncovered) > 0 {
			fmt.Fprintf(os.Stderr, "\neval FAILED: %d rule class(es) lack positive+negative corpus coverage:\n", len(uncovered))
			for _, class := range uncovered {
				fmt.Fprintf(os.Stderr, "  %s\n", class)
			}
			return exitError
		}

		perClassThreshold := perClassPrecisionThreshold(matcher.Rules())
		var failed []string
		for class, m := range result.Metrics {
			threshold, ok := perClassThreshold[class]
			if !ok {
				threshold = opts.minPrecision
			}
			if m.Precision < threshold || m.Recall < opts.minRecall {
				failed = append(failed, class)
			}
		}
		if len(failed) > 0 {
			fmt.Fprintf(os.Stderr, "\neval FAILED: %d class(es) below threshold:\n", len(failed))
			for _, class := range failed {
				m := result.Metrics[class]
				t := perClassThreshold[class]
				if t == 0 {
					t = opts.minPrecision
				}
				fmt.Fprintf(os.Stderr, "  %s: precision=%.4f (threshold=%.2f) recall=%.4f (threshold=%.2f)\n",
					class, m.Precision, t, m.Recall, opts.minRecall)
			}
			return exitFindings
		}
		fmt.Fprintf(os.Stderr, "\neval PASSED — all classes meet per-class precision thresholds\n")
		return nil
	}
	return fmt.Errorf("unknown eval mode %q", opts.mode)
}

// uncoveredRuleClasses returns the classes of loaded rules that lack BOTH a
// positive and a negative corpus entry. Such a rule ships unmeasured — precision
// needs negatives, recall needs positives — so `eval run` must fail rather than
// pass it silently (testing bar: every rule ships positive AND negative eval
// cases, gated in CI). The gate iterates result.Metrics, which only contains
// classes present in the corpus, so this is the check that catches the gap.
func uncoveredRuleClasses(rules []engine.Rule, corpus *evals.Corpus) []string {
	havePos := make(map[string]bool)
	haveNeg := make(map[string]bool)
	for _, e := range corpus.Entries {
		if e.ExpectFinding {
			havePos[e.Class] = true
		} else {
			haveNeg[e.Class] = true
		}
	}
	seen := make(map[string]bool)
	var uncovered []string
	for _, r := range rules {
		if seen[r.Class] {
			continue
		}
		seen[r.Class] = true
		if !havePos[r.Class] || !haveNeg[r.Class] {
			uncovered = append(uncovered, r.Class)
		}
	}
	sort.Strings(uncovered)
	return uncovered
}

// perClassPrecisionThreshold sets each class's eval-run precision floor to the
// rule's declared confidence minus a 0.05 tolerance, clamped to a hard 0.80
// floor (strictest wins across rules sharing a class). This is a per-rule
// regression guard — measured precision must stay within 0.05 of the confidence
// the rule ships with — NOT an independent quality bar. The absolute quality
// expectation lives in the corpus and the policy min_confidence gate; this only
// catches a rule drifting below its own recorded baseline.
func perClassPrecisionThreshold(rules []engine.Rule) map[string]float64 {
	thresholds := make(map[string]float64)
	for _, rule := range rules {
		conf := rule.Confidence
		if conf == 0 {
			conf = 1.0
		}
		threshold := conf - 0.05
		if threshold < 0.80 {
			threshold = 0.80
		}
		if existing, ok := thresholds[rule.Class]; !ok || threshold < existing {
			thresholds[rule.Class] = threshold
		}
	}
	return thresholds
}

func runScan(opts scanOptions) error {
	matcher, err := loadRules(opts.rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading rules from %s: %v\n", opts.rulesDir, err)
		return exitError
	}

	scanner := scan.NewScanner(matcher)
	results, err := scanner.Scan(opts.paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scanning: %v\n", err)
		return exitError
	}

	if opts.json {
		return outputJSON(os.Stdout, results)
	}
	return outputText(os.Stdout, results)
}

func outputJSON(w io.Writer, results []scan.Result) error {
	// Emit only files with findings, matching outputText — a full manifest of
	// every clean file is noise on a large scan. A clean scan prints "[]".
	withFindings := make([]scan.Result, 0, len(results))
	for _, r := range results {
		if len(r.Findings) > 0 {
			withFindings = append(withFindings, r)
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(withFindings); err != nil {
		fmt.Fprintf(os.Stderr, "error: json output: %v\n", err)
		return exitError
	}
	if len(withFindings) > 0 {
		return exitFindings
	}
	return nil
}

func outputText(w io.Writer, results []scan.Result) error {
	var findingsFound bool
	for _, r := range results {
		if len(r.Findings) == 0 {
			continue
		}
		findingsFound = true
		fmt.Fprintf(w, "%s:\n", r.Path)
		for _, f := range r.Findings {
			fmt.Fprintf(w, "  offset %d-%d  %s  %s  %.2f\n",
				f.Start, f.End, f.RuleID, f.Class, f.Confidence)
		}
	}
	if findingsFound {
		return exitFindings
	}
	return nil
}

func serve(opts serveOptions) error {
	cfg, err := loadServeConfig(opts)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	return serveConfig(cfg)
}

func loadServeConfig(opts serveOptions) (*policy.Config, error) {
	return policy.LoadConfig(opts.configPath)
}

func serveConfig(cfg *policy.Config) error {
	var ledgerWriter io.Writer = os.Stdout
	if cfg.Logger.Output != "" && cfg.Logger.Output != "stdout" {
		f, err := os.OpenFile(cfg.Logger.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("ledger output: %w", err)
		}
		defer f.Close()
		ledgerWriter = f
	}

	lw := ledger.NewWriter(ledgerWriter)

	matcher, err := loadRulesForConfig(cfg, "rules")
	if err != nil {
		return err
	}

	gw, err := gate.NewGateway(cfg, lw, matcher)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}

	httpServer := gw.HTTPServer()
	go func() {
		log.Printf("ContextShield serve starting on %s", cfg.Listen)
		if err := httpServer.ListenAndServe(); err != nil {
			log.Fatalf("serve: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
	return nil
}

func loadRulesForConfig(cfg *policy.Config, dir string) (*engine.Matcher, error) {
	matcher, err := loadRules(dir)
	if err == nil {
		return matcher, nil
	}
	if cfg.RequiresRules() {
		return nil, fmt.Errorf("rules: %w", err)
	}
	log.Printf("warning: loading rules: %v (continuing without detection; policy is log_only and on_error=open)", err)
	return nil, nil
}

func loadRules(dir string) (*engine.Matcher, error) {
	var rules []engine.Rule
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		rule, err := engine.ParseRuleYAML(data)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		rules = append(rules, rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules found in %s", dir)
	}
	return engine.NewMatcher(rules)
}

func printUsage(w io.Writer) {
	io.WriteString(w, "ContextShield - egress policy + evidence layer for AI traffic\n\n")
	io.WriteString(w, "Usage:\n")
	io.WriteString(w, "  contextshield serve [flags]\n")
	io.WriteString(w, "  contextshield [flags]         compatibility alias for serve\n")
	io.WriteString(w, "  contextshield scan [flags] [path ...]\n")
	io.WriteString(w, "  contextshield eval run [flags]\n")
	io.WriteString(w, "  contextshield eval render [flags]\n\n")
	io.WriteString(w, "Commands:\n")
	io.WriteString(w, "  serve    Run the gateway server\n")
	io.WriteString(w, "  scan     Scan files and directories for secrets\n")
	io.WriteString(w, "  eval     Run or render the eval corpus\n\n")
	io.WriteString(w, "Flags:\n")
	io.WriteString(w, "  -config string\n")
	io.WriteString(w, "        path to shield.yaml (default \"shield.yaml\")\n")
}
