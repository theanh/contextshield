package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	content := `
listen: ":9090"
upstreams:
  openai: https://api.openai.com
`
	f, err := os.CreateTemp("", "shield-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cfg, err := LoadConfig(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9090" {
		t.Fatalf("expected :9090, got %s", cfg.Listen)
	}
	if cfg.Defaults.Action != "log_only" {
		t.Fatalf("expected log_only, got %s", cfg.Defaults.Action)
	}
	if cfg.Defaults.OnError != "closed" {
		t.Fatalf("expected closed, got %s", cfg.Defaults.OnError)
	}
	if cfg.Upstreams["openai"] != "https://api.openai.com" {
		t.Fatalf("unexpected upstream: %v", cfg.Upstreams)
	}
}

func TestLoadConfigMissingUpstreams(t *testing.T) {
	content := `listen: ":8080"`
	f, err := os.CreateTemp("", "shield-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	_, err = LoadConfig(f.Name())
	if err == nil {
		t.Fatal("expected error for missing upstreams")
	}
}

func TestLoadConfigInvalidFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/shield.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadConfigRejectsInvalidActionsAndOnError(t *testing.T) {
	cases := []struct {
		name          string
		content       string
		wantErrSubstr string
	}{
		{
			name: "invalid default action",
			content: `
listen: ":8080"
upstreams:
  openai: https://api.openai.com
defaults:
  action: blok
  on_error: closed
`,
			wantErrSubstr: `defaults.action "blok"`,
		},
		{
			name: "invalid rule action",
			content: `
listen: ":8080"
upstreams:
  openai: https://api.openai.com
rules:
  - classes: ["secret.*"]
    action: blok
`,
			wantErrSubstr: `rules[0].action "blok"`,
		},
		{
			name: "invalid on error",
			content: `
listen: ":8080"
upstreams:
  openai: https://api.openai.com
defaults:
  action: log_only
  on_error: fail_closed
`,
			wantErrSubstr: `defaults.on_error "fail_closed"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "shield.yaml")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}

			_, err := LoadConfig(path)
			if err == nil {
				t.Fatal("expected invalid config to fail")
			}
			if !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Fatalf("expected error to contain %q, got %q", tc.wantErrSubstr, err.Error())
			}
		})
	}
}

func TestRequiresRules(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{
			name: "closed requires rules",
			cfg:  Config{Defaults: Defaults{Action: "log_only", OnError: "closed"}},
			want: true,
		},
		{
			name: "default block requires rules",
			cfg:  Config{Defaults: Defaults{Action: "block", OnError: "open"}},
			want: true,
		},
		{
			name: "block rule requires rules",
			cfg: Config{
				Defaults: Defaults{Action: "log_only", OnError: "open"},
				Rules:    []Rule{{Classes: []string{"secret.*"}, Action: "block"}},
			},
			want: true,
		},
		{
			name: "mask rule requires rules",
			cfg: Config{
				Defaults: Defaults{Action: "log_only", OnError: "open"},
				Rules:    []Rule{{Classes: []string{"regulated.*"}, Action: "mask"}},
			},
			want: true,
		},
		{
			name: "log only open does not require rules",
			cfg:  Config{Defaults: Defaults{Action: "log_only", OnError: "open"}},
			want: false,
		},
		{
			name: "log only rule with open does not require rules",
			cfg: Config{
				Defaults: Defaults{Action: "log_only", OnError: "open"},
				Rules:    []Rule{{Classes: []string{"pii.email"}, Action: "log_only"}},
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.RequiresRules()
			if got != tc.want {
				t.Fatalf("RequiresRules() = %v, want %v", got, tc.want)
			}
		})
	}
}
