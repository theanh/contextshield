package engine

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

func ParseRuleYAML(data []byte) (Rule, error) {
	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return Rule{}, fmt.Errorf("parse rule yaml: %w", err)
	}
	if err := validateRule(rule); err != nil {
		return Rule{}, err
	}
	return rule, nil
}

func ParseRulesYAML(docs ...[]byte) ([]Rule, error) {
	rules := make([]Rule, 0, len(docs))
	for _, doc := range docs {
		rule, err := ParseRuleYAML(doc)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}
