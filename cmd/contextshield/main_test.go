package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/theanh/contextshield/engine"
	"github.com/theanh/contextshield/evals"
	"github.com/theanh/contextshield/policy"
	"github.com/theanh/contextshield/scan"
)

func TestParseCommandConfigFlag(t *testing.T) {
	cases := []struct {
		name           string
		args           []string
		wantConfigPath string
	}{
		{
			name:           "explicit serve subcommand",
			args:           []string{"serve", "-config", "/tmp/contextshield-explicit.yaml"},
			wantConfigPath: "/tmp/contextshield-explicit.yaml",
		},
		{
			name:           "legacy serve alias",
			args:           []string{"-config", "/tmp/contextshield-legacy.yaml"},
			wantConfigPath: "/tmp/contextshield-legacy.yaml",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := parseCommand(tc.args, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if cmd.name != "serve" {
				t.Fatalf("expected serve command, got %q", cmd.name)
			}
			if cmd.serve.configPath != tc.wantConfigPath {
				t.Fatalf("expected config path %q, got %q", tc.wantConfigPath, cmd.serve.configPath)
			}
		})
	}
}

func TestServeConfigFlagLoadsExplicitConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom-shield.yaml")
	config := []byte(`
listen: ":19091"
upstreams:
  test: http://127.0.0.1:9
`)
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}

	cmd, err := parseCommand([]string{"serve", "-config", configPath}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := loadServeConfig(cmd.serve)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Listen != ":19091" {
		t.Fatalf("expected explicit config listen :19091, got %q", cfg.Listen)
	}
	if cfg.Upstreams["test"] != "http://127.0.0.1:9" {
		t.Fatalf("expected explicit upstream, got %v", cfg.Upstreams)
	}
}

func TestServeConfigFlagReportsMissingExplicitConfig(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing-shield.yaml")

	err := run([]string{"serve", "-config", missingPath}, io.Discard)
	if err == nil {
		t.Fatal("expected missing explicit config path to fail")
	}
	if !strings.Contains(err.Error(), missingPath) {
		t.Fatalf("expected error to mention explicit config path %q, got %q", missingPath, err.Error())
	}
}

func TestLoadRulesForConfigFailsWhenRulesRequired(t *testing.T) {
	cases := []struct {
		name string
		cfg  *policy.Config
	}{
		{
			name: "closed requires loaded rules",
			cfg: &policy.Config{
				Defaults: policy.Defaults{Action: "log_only", OnError: "closed"},
			},
		},
		{
			name: "default block requires loaded rules",
			cfg: &policy.Config{
				Defaults: policy.Defaults{Action: "block", OnError: "open"},
			},
		},
		{
			name: "block rule requires loaded rules",
			cfg: &policy.Config{
				Defaults: policy.Defaults{Action: "log_only", OnError: "open"},
				Rules:    []policy.Rule{{Classes: []string{"secret.*"}, Action: "block"}},
			},
		},
		{
			name: "mask rule requires loaded rules",
			cfg: &policy.Config{
				Defaults: policy.Defaults{Action: "log_only", OnError: "open"},
				Rules:    []policy.Rule{{Classes: []string{"regulated.*"}, Action: "mask"}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadRulesForConfig(tc.cfg, filepath.Join(t.TempDir(), "missing-rules"))
			if err == nil {
				t.Fatal("expected required rules to fail startup")
			}
			if !strings.Contains(err.Error(), "rules:") {
				t.Fatalf("expected rules error, got %q", err.Error())
			}
		})
	}
}

func TestLoadRulesForConfigAllowsExplicitObservationOpenWithoutRules(t *testing.T) {
	cases := []struct {
		name string
		cfg  *policy.Config
	}{
		{
			name: "default log only open",
			cfg: &policy.Config{
				Defaults: policy.Defaults{Action: "log_only", OnError: "open"},
			},
		},
		{
			name: "rule log only open",
			cfg: &policy.Config{
				Defaults: policy.Defaults{Action: "log_only", OnError: "open"},
				Rules:    []policy.Rule{{Classes: []string{"pii.email"}, Action: "log_only"}},
			},
		},
	}

	oldOutput := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(oldOutput)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := loadRulesForConfig(tc.cfg, filepath.Join(t.TempDir(), "missing-rules"))
			if err != nil {
				t.Fatal(err)
			}
			if matcher != nil {
				t.Fatal("expected nil matcher when observation-only config explicitly opens rule-load failures")
			}
		})
	}
}

// TestUncoveredRuleClasses covers the eval-run gate that fails when a loaded
// rule's class lacks positive+negative corpus coverage — otherwise the rule
// ships unmeasured and eval run passes it silently.
func TestUncoveredRuleClasses(t *testing.T) {
	rules := []engine.Rule{
		{ID: "a", Class: "secret.a"},
		{ID: "b", Class: "secret.b"},
	}
	cases := []struct {
		name    string
		entries []evals.Entry
		want    []string
	}{
		{
			name: "both classes have positive and negative coverage",
			entries: []evals.Entry{
				{Class: "secret.a", ExpectFinding: true},
				{Class: "secret.a", ExpectFinding: false},
				{Class: "secret.b", ExpectFinding: true},
				{Class: "secret.b", ExpectFinding: false},
			},
			want: nil,
		},
		{
			name: "class with only positive entries is uncovered",
			entries: []evals.Entry{
				{Class: "secret.a", ExpectFinding: true},
				{Class: "secret.a", ExpectFinding: false},
				{Class: "secret.b", ExpectFinding: true},
			},
			want: []string{"secret.b"},
		},
		{
			name: "class absent from the corpus is uncovered",
			entries: []evals.Entry{
				{Class: "secret.a", ExpectFinding: true},
				{Class: "secret.a", ExpectFinding: false},
			},
			want: []string{"secret.b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := uncoveredRuleClasses(rules, &evals.Corpus{Entries: tc.entries})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("uncoveredRuleClasses = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestScanOutputJSONOmitsCleanFiles covers the scan JSON output: only files
// with findings are emitted (matching the text output), and a clean scan is an
// empty array with a no-findings exit.
func TestScanOutputJSONOmitsCleanFiles(t *testing.T) {
	finding := engine.Finding{RuleID: "r", Class: "secret.test", Start: 0, End: 4, Confidence: 1.0}
	cases := []struct {
		name      string
		results   []scan.Result
		wantPaths []string
		wantExit  error
	}{
		{
			name: "clean files omitted, dirty kept",
			results: []scan.Result{
				{Path: "clean.txt"},
				{Path: "dirty.txt", Findings: []engine.Finding{finding}},
			},
			wantPaths: []string{"dirty.txt"},
			wantExit:  exitFindings,
		},
		{
			name: "all clean emits empty array and no findings exit",
			results: []scan.Result{
				{Path: "a.txt"},
				{Path: "b.txt"},
			},
			wantPaths: []string{},
			wantExit:  nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := outputJSON(&buf, tc.results)
			if err != tc.wantExit {
				t.Fatalf("exit = %v, want %v", err, tc.wantExit)
			}
			var got []scan.Result
			if e := json.Unmarshal(buf.Bytes(), &got); e != nil {
				t.Fatalf("output is not valid JSON: %v (%q)", e, buf.String())
			}
			gotPaths := []string{}
			for _, r := range got {
				gotPaths = append(gotPaths, r.Path)
			}
			if !reflect.DeepEqual(gotPaths, tc.wantPaths) {
				t.Fatalf("paths = %v, want %v", gotPaths, tc.wantPaths)
			}
		})
	}
}
