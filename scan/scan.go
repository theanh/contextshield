package scan

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/theanh/contextshield/engine"
)

type Result struct {
	Path     string           `json:"path"`
	Findings []engine.Finding `json:"findings"`
}

type Scanner struct {
	matcher *engine.Matcher
}

func NewScanner(matcher *engine.Matcher) *Scanner {
	return &Scanner{matcher: matcher}
}

func (s *Scanner) Scan(paths []string) ([]Result, error) {
	if s == nil || s.matcher == nil {
		return nil, nil
	}
	var results []Result
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			dirResults, err := s.scanDir(path)
			if err != nil {
				return nil, err
			}
			results = append(results, dirResults...)
		} else {
			result, err := s.scanFile(path)
			if err != nil {
				return nil, err
			}
			results = append(results, result)
		}
	}
	return results, nil
}

func (s *Scanner) scanDir(dir string) ([]Result, error) {
	var results []Result
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		result, err := s.scanFile(path)
		if err != nil {
			return err
		}
		results = append(results, result)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (s *Scanner) scanFile(path string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	findings := s.matcher.Find(data)
	return Result{Path: path, Findings: findings}, nil
}
