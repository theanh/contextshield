package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/theanh/contextshield/engine"
)

func TestScannerReportsFindings(t *testing.T) {
	matcher, err := engine.NewMatcher([]engine.Rule{{
		ID:          "aws-access-key-id",
		Class:       "secret.aws_access_key",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(matcher)

	tests := []struct {
		name     string
		content  string
		wantFind bool
		ruleID   string
		class    string
	}{
		{name: "clean file produces no findings", content: "hello world\nno secrets here\n", wantFind: false},
		{name: "aws key produces finding", content: "AKIAIOSFODNN7EXAMPLE\n", wantFind: true, ruleID: "aws-access-key-id", class: "secret.aws_access_key"},
		{name: "lowercase aws key does not match", content: "akiaiosfodnn7example\n", wantFind: false},
		{name: "truncated aws key does not match", content: "AKIAIOSFODNN7EXAMPL\n", wantFind: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "test.txt")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}
			results, err := scanner.Scan([]string{path})
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			if results[0].Path != path {
				t.Fatalf("expected path %q, got %q", path, results[0].Path)
			}
			found := len(results[0].Findings) > 0
			if found != tt.wantFind {
				t.Fatalf("wantFind=%v, got %d findings", tt.wantFind, len(results[0].Findings))
			}
			if tt.wantFind {
				f := results[0].Findings[0]
				if f.RuleID != tt.ruleID {
					t.Fatalf("expected rule %q, got %q", tt.ruleID, f.RuleID)
				}
				if f.Class != tt.class {
					t.Fatalf("expected class %q, got %q", tt.class, f.Class)
				}
				if f.Confidence != 1.0 {
					t.Fatalf("expected confidence 1.0, got %f", f.Confidence)
				}
				if f.Start < 0 || f.End > len(tt.content) || f.Start >= f.End {
					t.Fatalf("invalid offsets: start=%d end=%d contentLen=%d", f.Start, f.End, len(tt.content))
				}
			}
		})
	}
}

func TestScannerDirectoryWalk(t *testing.T) {
	matcher, err := engine.NewMatcher([]engine.Rule{{
		ID:          "aws-access-key-id",
		Class:       "secret.aws_access_key",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(matcher)

	dir := t.TempDir()
	cleanFile := filepath.Join(dir, "README.md")
	dirtyFile := filepath.Join(dir, "config.txt")
	nestedDir := filepath.Join(dir, "subdir")
	nestedFile := filepath.Join(nestedDir, "secret.env")

	if err := os.WriteFile(cleanFile, []byte("hello world\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dirtyFile, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nestedFile, []byte("also AKIA1234567890123456\n"), 0644); err != nil {
		t.Fatal(err)
	}

	results, err := scanner.Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results (3 files), got %d", len(results))
	}
	var dirtyCount int
	for _, r := range results {
		if len(r.Findings) > 0 {
			dirtyCount++
		}
	}
	if dirtyCount != 2 {
		t.Fatalf("expected 2 files with findings, got %d", dirtyCount)
	}
}

func TestScannerMultiplePaths(t *testing.T) {
	matcher, err := engine.NewMatcher([]engine.Rule{{
		ID:          "aws-access-key-id",
		Class:       "secret.aws_access_key",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(matcher)

	dir := t.TempDir()
	cleanFile := filepath.Join(dir, "clean.txt")
	dirtyFile := filepath.Join(dir, "secret.txt")

	if err := os.WriteFile(cleanFile, []byte("nothing here\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dirtyFile, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644); err != nil {
		t.Fatal(err)
	}

	results, err := scanner.Scan([]string{cleanFile, dirtyFile})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if len(results[0].Findings) > 0 {
		t.Fatalf("clean file should have no findings, got %d", len(results[0].Findings))
	}
	if len(results[1].Findings) != 1 {
		t.Fatalf("dirty file should have 1 finding, got %d", len(results[1].Findings))
	}
}

func TestScannerNilMatcher(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644); err != nil {
		t.Fatal(err)
	}

	results, err := (*Scanner)(nil).Scan([]string{path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results from nil scanner, got %d", len(results))
	}

	results, err = NewScanner(nil).Scan([]string{path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results from nil-matcher scanner, got %d", len(results))
	}
}

func TestScannerBadPath(t *testing.T) {
	matcher, err := engine.NewMatcher([]engine.Rule{{
		ID:          "aws-access-key-id",
		Class:       "secret.aws_access_key",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(matcher)
	_, err = scanner.Scan([]string{"/nonexistent/path/here"})
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}
