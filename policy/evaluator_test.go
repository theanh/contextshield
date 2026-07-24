package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestActionByClassGlob(t *testing.T) {
	cfg := &Config{
		Defaults: Defaults{Action: "log_only", OnError: "closed"},
		Rules: []Rule{
			{Classes: []string{"secret.*"}, Action: "block"},
			{Classes: []string{"regulated.*"}, Action: "mask"},
			{Classes: []string{"structural.ssn"}, Action: "mask", MinConfidence: p(0.85)},
		},
	}
	e := NewEvaluator(cfg)

	tests := []struct {
		class      string
		confidence float64
		want       Action
		exempted   bool
	}{
		{class: "secret.aws_access_key", confidence: 1.0, want: ActionBlock},
		{class: "secret.generic", confidence: 0.75, want: ActionBlock},
		{class: "regulated.credit_card", confidence: 1.0, want: ActionMask},
		{class: "regulated.iban", confidence: 1.0, want: ActionMask},
		{class: "structural.ssn", confidence: 0.9, want: ActionMask},
		{class: "unknown.class", confidence: 1.0, want: ActionLogOnly},
	}

	for _, tc := range tests {
		got := e.Evaluate(tc.class, "api.openai.com", tc.confidence)
		if got.Action != tc.want {
			t.Errorf("Evaluate(%q, api.openai.com, %.2f) = %v, want %v", tc.class, tc.confidence, got.Action, tc.want)
		}
		if got.Exempted != tc.exempted {
			t.Errorf("Evaluate(%q, ...).Exempted = %v, want %v", tc.class, got.Exempted, tc.exempted)
		}
	}
}

func TestMinConfidenceFallback(t *testing.T) {
	cfg := &Config{
		Defaults: Defaults{Action: "log_only", OnError: "closed"},
		Rules: []Rule{
			{Classes: []string{"structural.ssn"}, Action: "mask", MinConfidence: p(0.85)},
		},
	}
	e := NewEvaluator(cfg)

	above := e.Evaluate("structural.ssn", "api.anthropic.com", 0.9)
	if above.Action != ActionMask {
		t.Fatalf("above threshold: expected mask, got %v", above.Action)
	}

	below := e.Evaluate("structural.ssn", "api.anthropic.com", 0.7)
	if below.Action != ActionLogOnly {
		t.Fatalf("below threshold: expected log_only (defaults.action), got %v", below.Action)
	}
	if below.Exempted {
		t.Fatal("below threshold should not be exempted")
	}
}

func TestMinConfidenceNeverAutoBlock(t *testing.T) {
	cfg := &Config{
		Defaults: Defaults{Action: "block", OnError: "closed"},
		Rules: []Rule{
			{Classes: []string{"structural.ssn"}, Action: "mask", MinConfidence: p(0.85)},
		},
	}
	e := NewEvaluator(cfg)

	result := e.Evaluate("structural.ssn", "api.anthropic.com", 0.7)
	if result.Action != ActionLogOnly {
		t.Fatalf("below threshold with defaults.action='block': expected log_only (never auto-block), got %v", result.Action)
	}
}

func TestExemptionExactMatch(t *testing.T) {
	cfg := &Config{
		Defaults: Defaults{Action: "log_only", OnError: "closed"},
		Rules: []Rule{
			{Classes: []string{"secret.*"}, Action: "block"},
		},
		Exemptions: []Exemption{
			{Class: "secret.weather_api_key", Destination: "api.weather.example.com"},
		},
	}
	e := NewEvaluator(cfg)

	matching := e.Evaluate("secret.weather_api_key", "api.weather.example.com", 1.0)
	if !matching.Exempted {
		t.Fatal("expected exemption to match")
	}
	if matching.Action != ActionLogOnly {
		t.Fatalf("exempted: expected log_only, got %v", matching.Action)
	}

	differentDest := e.Evaluate("secret.weather_api_key", "api.openai.com", 1.0)
	if differentDest.Exempted {
		t.Fatal("expected exemption to NOT match different destination")
	}
	if differentDest.Action != ActionBlock {
		t.Fatalf("different destination: expected block (rule action), got %v", differentDest.Action)
	}

	differentClass := e.Evaluate("secret.aws_access_key", "api.weather.example.com", 1.0)
	if differentClass.Exempted {
		t.Fatal("expected exemption to NOT match different class")
	}
	if differentClass.Action != ActionBlock {
		t.Fatalf("different class: expected block (rule action), got %v", differentClass.Action)
	}
}

func TestExemptedStillEmitsLedgerLine(t *testing.T) {
	cfg := &Config{
		Defaults: Defaults{Action: "log_only", OnError: "closed"},
		Rules: []Rule{
			{Classes: []string{"secret.*"}, Action: "block"},
		},
		Exemptions: []Exemption{
			{Class: "secret.weather_api_key", Destination: "api.weather.example.com"},
		},
	}
	e := NewEvaluator(cfg)

	result := e.Evaluate("secret.weather_api_key", "api.weather.example.com", 1.0)
	if !result.Exempted {
		t.Fatal("exempted finding should have Exempted=true")
	}
}

func TestDefaultActionWhenNoRuleMatches(t *testing.T) {
	cfg := &Config{
		Defaults: Defaults{Action: "mask", OnError: "closed"},
	}
	e := NewEvaluator(cfg)

	result := e.Evaluate("unknown.class", "api.openai.com", 1.0)
	if result.Action != ActionMask {
		t.Fatalf("no matching rule: expected defaults.action, got %v", result.Action)
	}
}

func TestHasBlockRule(t *testing.T) {
	withBlock := &Config{
		Rules: []Rule{
			{Classes: []string{"secret.*"}, Action: "block"},
		},
	}
	if !NewEvaluator(withBlock).HasBlockRule() {
		t.Fatal("expected HasBlockRule true")
	}

	withoutBlock := &Config{
		Rules: []Rule{
			{Classes: []string{"regulated.*"}, Action: "mask"},
		},
	}
	if NewEvaluator(withoutBlock).HasBlockRule() {
		t.Fatal("expected HasBlockRule false")
	}

	empty := &Config{}
	if NewEvaluator(empty).HasBlockRule() {
		t.Fatal("expected HasBlockRule false for empty config")
	}
}

func TestOnErrorDefault(t *testing.T) {
	cfg := &Config{
		Defaults: Defaults{Action: "log_only", OnError: "closed"},
	}
	e := NewEvaluator(cfg)
	if e.OnError() != "closed" {
		t.Fatalf("expected on_error=closed, got %q", e.OnError())
	}
}

func TestOnErrorOpen(t *testing.T) {
	cfg := &Config{
		Defaults: Defaults{Action: "log_only", OnError: "open"},
	}
	e := NewEvaluator(cfg)
	if e.OnError() != "open" {
		t.Fatalf("expected on_error=open, got %q", e.OnError())
	}
}

func TestBlockErrorOpenAI(t *testing.T) {
	detail := BlockDetail{
		Class:     "secret.aws_access_key",
		RuleID:    "aws-access-key-id",
		RequestID: "r_test123",
	}

	status, body := BlockErrorForPath("/v1/chat/completions", "request", detail)
	if status != 403 {
		t.Fatalf("expected 403, got %d", status)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	errObj, ok := parsed["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing error wrapper: %+v", parsed)
	}

	if code := errObj["code"]; code != "contextshield_blocked" {
		t.Fatalf("expected code contextshield_blocked, got %v", code)
	}
	if tp := errObj["type"]; tp != "contextshield_blocked" {
		t.Fatalf("expected type contextshield_blocked, got %v", tp)
	}

	detailMap, ok := errObj["detail"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing detail in error: %+v", errObj)
	}
	if detailMap["class"] != "secret.aws_access_key" {
		t.Fatalf("unexpected class in detail: %v", detailMap["class"])
	}
	if detailMap["rule_id"] != "aws-access-key-id" {
		t.Fatalf("unexpected rule_id in detail: %v", detailMap["rule_id"])
	}
	if detailMap["request_id"] != "r_test123" {
		t.Fatalf("unexpected request_id in detail: %v", detailMap["request_id"])
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "AKIA") {
		t.Fatal("block error must never contain matched value")
	}
}

func TestBlockErrorAnthropic(t *testing.T) {
	detail := BlockDetail{
		Class:     "secret.aws_access_key",
		RuleID:    "aws-access-key-id",
		RequestID: "r_test456",
	}

	status, body := BlockErrorForPath("/v1/messages", "request", detail)
	if status != 403 {
		t.Fatalf("expected 403, got %d", status)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if tp := parsed["type"]; tp != "error" {
		t.Fatalf("expected type=error, got %v", tp)
	}

	errObj, ok := parsed["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing error wrapper: %+v", parsed)
	}
	if tp := errObj["type"]; tp != "contextshield_blocked" {
		t.Fatalf("expected type contextshield_blocked, got %v", tp)
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "AKIA") {
		t.Fatal("block error must never contain matched value")
	}
}

func TestBlockErrorForResponsesEndpoint(t *testing.T) {
	detail := BlockDetail{
		Class:     "regulated.credit_card",
		RuleID:    "credit-card-pan",
		RequestID: "r_resp789",
	}

	status, body := BlockErrorForPath("/v1/responses", "request", detail)
	if status != 403 {
		t.Fatalf("expected 403, got %d", status)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	errObj, ok := parsed["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing error wrapper for responses endpoint: %+v", parsed)
	}
	if code := errObj["code"]; code != "contextshield_blocked" {
		t.Fatalf("expected code contextshield_blocked for responses, got %v", code)
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "4111") {
		t.Fatal("block error must never contain matched value")
	}
}

// TestBlockErrorMessageReflectsDirection pins that the block error's message
// text tracks which side was actually blocked. applyActions (gate/gateway.go)
// is shared by the request-side scan and the non-streaming response-side
// scan, so a message that always says "request" is wrong whenever a model's
// RESPONSE is what triggered the block. Data-provider over path x direction.
func TestBlockErrorMessageReflectsDirection(t *testing.T) {
	detail := BlockDetail{Class: "secret.aws_access_key", RuleID: "aws-access-key-id", RequestID: "r_1"}
	cases := []struct {
		name        string
		path        string
		direction   string
		wantMessage string
	}{
		{"openai request", "/v1/chat/completions", "request", "Request blocked by ContextShield policy"},
		{"openai response", "/v1/chat/completions", "response", "Response blocked by ContextShield policy"},
		{"anthropic request", "/v1/messages", "request", "request blocked by ContextShield policy"},
		{"anthropic response", "/v1/messages", "response", "response blocked by ContextShield policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, body := BlockErrorForPath(tc.path, tc.direction, detail)
			var parsed map[string]interface{}
			if err := json.Unmarshal(body, &parsed); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			errObj := parsed["error"].(map[string]interface{})
			if msg := errObj["message"]; msg != tc.wantMessage {
				t.Fatalf("message = %q, want %q", msg, tc.wantMessage)
			}
		})
	}
}

func p(v float64) *float64 {
	return &v
}
