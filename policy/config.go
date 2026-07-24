package policy

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	OnErrorClosed = "closed"
	OnErrorOpen   = "open"
)

var validOnErrors = map[string]bool{
	OnErrorClosed: true,
	OnErrorOpen:   true,
}

type Config struct {
	Listen     string            `yaml:"listen"`
	Upstreams  map[string]string `yaml:"upstreams"`
	Defaults   Defaults          `yaml:"defaults"`
	Rules      []Rule            `yaml:"rules"`
	Exemptions []Exemption       `yaml:"exemptions"`
	Logger     LoggerConfig      `yaml:"logger"`
}

type Defaults struct {
	Action  string `yaml:"action"`
	OnError string `yaml:"on_error"`
}

type Rule struct {
	Classes       []string `yaml:"classes"`
	Action        string   `yaml:"action"`
	MinConfidence *float64 `yaml:"min_confidence,omitempty"`
}

type Exemption struct {
	Class       string `yaml:"class"`
	Destination string `yaml:"destination"`
}

type LoggerConfig struct {
	Output string `yaml:"output"`
}

func DefaultConfig() *Config {
	return &Config{
		Listen: ":8080",
		Defaults: Defaults{
			Action:  "log_only",
			OnError: "closed",
		},
		Upstreams: map[string]string{},
		Logger: LoggerConfig{
			Output: "stdout",
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if len(cfg.Upstreams) == 0 {
		return nil, fmt.Errorf("config: at least one upstream required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (cfg *Config) Validate() error {
	if !validAction(cfg.Defaults.Action) {
		return fmt.Errorf("config: defaults.action %q must be one of %s", cfg.Defaults.Action, actionList())
	}
	if !validOnErrors[cfg.Defaults.OnError] {
		return fmt.Errorf("config: defaults.on_error %q must be one of closed, open", cfg.Defaults.OnError)
	}
	for i, rule := range cfg.Rules {
		if !validAction(rule.Action) {
			return fmt.Errorf("config: rules[%d].action %q must be one of %s", i, rule.Action, actionList())
		}
	}
	return nil
}

func (cfg *Config) RequiresRules() bool {
	if cfg.Defaults.OnError == OnErrorClosed {
		return true
	}
	if cfg.Defaults.Action != string(ActionLogOnly) {
		return true
	}
	for _, rule := range cfg.Rules {
		if rule.Action != string(ActionLogOnly) {
			return true
		}
	}
	return false
}

func validAction(action string) bool {
	_, ok := validActions[Action(action)]
	return ok
}

func actionList() string {
	actions := []string{string(ActionBlock), string(ActionMask), string(ActionLogOnly)}
	return strings.Join(actions, ", ")
}
