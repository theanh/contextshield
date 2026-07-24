package policy

import "path/filepath"

type EvalResult struct {
	Action   Action
	Exempted bool
}

type Evaluator struct {
	config *Config
}

func NewEvaluator(cfg *Config) *Evaluator {
	return &Evaluator{config: cfg}
}

func (e *Evaluator) Evaluate(class, destination string, confidence float64) EvalResult {
	defaultAction := toAction(e.config.Defaults.Action)

	for _, ex := range e.config.Exemptions {
		if ex.Class == class && ex.Destination == destination {
			return EvalResult{Action: ActionLogOnly, Exempted: true}
		}
	}

	for _, rule := range e.config.Rules {
		for _, classGlob := range rule.Classes {
			if matched, _ := filepath.Match(classGlob, class); matched {
				ruleAction := toAction(rule.Action)

				if rule.MinConfidence != nil && confidence < *rule.MinConfidence {
					if defaultAction == ActionBlock {
						return EvalResult{Action: ActionLogOnly}
					}
					return EvalResult{Action: defaultAction}
				}

				return EvalResult{Action: ruleAction}
			}
		}
	}

	return EvalResult{Action: defaultAction}
}

func (e *Evaluator) HasBlockRule() bool {
	for _, rule := range e.config.Rules {
		if rule.Action == string(ActionBlock) {
			return true
		}
	}
	return false
}

func (e *Evaluator) OnError() string {
	return e.config.Defaults.OnError
}

func toAction(s string) Action {
	a := Action(s)
	if _, ok := validActions[a]; ok {
		return a
	}
	return ActionLogOnly
}
