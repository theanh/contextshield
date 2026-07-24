package engine

type Rule struct {
	ID          string   `yaml:"id"`
	Class       string   `yaml:"class"`
	Severity    string   `yaml:"severity,omitempty"`
	Pattern     string   `yaml:"pattern"`
	MaxMatchLen int      `yaml:"max_match_len"`
	Keywords    []string `yaml:"keywords,omitempty"`
	Prefilter   string   `yaml:"prefilter,omitempty"`
	Validators  []string `yaml:"validators,omitempty"`
	Confidence  float64  `yaml:"confidence,omitempty"`
	MatchGroup  int      `yaml:"match_group,omitempty"`
	Examples    Examples `yaml:"examples,omitempty"`
}

type Examples struct {
	Positive []string `yaml:"positive"`
	Negative []string `yaml:"negative"`
}

type Finding struct {
	RuleID     string  `json:"rule_id"`
	Class      string  `json:"class"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
}
