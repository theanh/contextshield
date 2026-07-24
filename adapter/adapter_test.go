package adapter

import (
	"strings"
	"testing"

	"github.com/theanh/contextshield/engine"
)

func TestExtractChatDecodedEscapedSecretScans(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"deploy AKIA\u0049OSFODNN7EXAMPLE"}]}`)
	rule := engine.Rule{
		ID:          "aws-access-key-id",
		Class:       "secret.aws_access_key",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}
	matcher, err := engine.NewMatcher([]engine.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}

	if findings := matcher.Find(body); len(findings) != 0 {
		t.Fatalf("raw escaped JSON body should not match directly: %+v", findings)
	}

	result, err := Extract("/v1/chat/completions", body)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Units) != 1 {
		t.Fatalf("expected one scan unit, got %+v", result.Units)
	}
	if result.Units[0].Path != "$.messages[0].content" {
		t.Fatalf("expected content path, got %q", result.Units[0].Path)
	}
	if result.Units[0].Text != "deploy AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("expected decoded content, got %q", result.Units[0].Text)
	}

	findings := matcher.Find([]byte(result.Units[0].Text))
	if len(findings) != 1 {
		t.Fatalf("expected decoded scan unit to match, got %+v", findings)
	}
	rawStart, rawEnd, ok := result.Units[0].RawSpan(findings[0].Start, findings[0].End)
	if !ok {
		t.Fatal("expected decoded finding span to map to raw JSON bytes")
	}
	if string(body[rawStart:rawEnd]) != `AKIA\u0049OSFODNN7EXAMPLE` {
		t.Fatalf("expected raw escaped span, got %q", string(body[rawStart:rawEnd]))
	}
}

func TestStructuralJSONIsNotScannedAsRawText(t *testing.T) {
	body := []byte(`{"model":"AKIAIOSFODNN7EXAMPLE","messages":[{"role":"AKIAIOSFODNN7EXAMPLE","content":[{"type":"AKIAIOSFODNN7EXAMPLE"}]}],"stream":false}`)
	rule := engine.Rule{
		ID:          "aws-access-key-id",
		Class:       "secret.aws_access_key",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}
	matcher, err := engine.NewMatcher([]engine.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}

	if findings := matcher.Find(body); len(findings) == 0 {
		t.Fatal("test setup expected raw-body scanning to find the structural string")
	}

	result, err := Extract("/v1/chat/completions", body)
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range result.Units {
		if findings := matcher.Find([]byte(unit.Text)); len(findings) != 0 {
			t.Fatalf("structural field leaked into scan unit %+v with findings %+v", unit, findings)
		}
	}
}

func TestToolArgumentNestedJSONEscapesScanDecodedValue(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"assistant","tool_calls":[{"type":"function","function":{"name":"lookup","arguments":"{\"key\":\"AKIA\\u0049OSFODNN7EXAMPLE\"}"}}]}]}`)
	rule := engine.Rule{
		ID:          "aws-access-key-id",
		Class:       "secret.aws_access_key",
		Pattern:     `\bAKIA[0-9A-Z]{16}\b`,
		MaxMatchLen: 20,
		Keywords:    []string{"AKIA"},
	}
	matcher, err := engine.NewMatcher([]engine.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}

	result, err := Extract("/v1/chat/completions", body)
	if err != nil {
		t.Fatal(err)
	}

	var argumentValue ScanUnit
	for _, unit := range result.Units {
		if unit.Path == "$.messages[0].tool_calls[0].function.arguments.key" {
			argumentValue = unit
		}
	}
	if argumentValue.Text != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("expected decoded nested argument value, got %+v", result.Units)
	}
	findings := matcher.Find([]byte(argumentValue.Text))
	if len(findings) != 1 {
		t.Fatalf("expected nested argument value to match, got %+v", findings)
	}
	rawStart, rawEnd, ok := argumentValue.RawSpan(findings[0].Start, findings[0].End)
	if !ok {
		t.Fatal("expected nested argument finding span to map to raw JSON bytes")
	}
	if string(body[rawStart:rawEnd]) != `AKIA\\u0049OSFODNN7EXAMPLE` {
		t.Fatalf("expected raw double-escaped span, got %q", string(body[rawStart:rawEnd]))
	}
}

func TestExtractsKnownTextFieldsByProvider(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want map[string]string
	}{
		{
			name: "openai chat completions",
			path: "/v1/chat/completions",
			body: `{
				"model":"gpt-4o",
				"messages":[
					{"role":"system","content":[{"type":"text","text":"chat array text"}]},
					{"role":"assistant","tool_calls":[{"type":"function","function":{"name":"lookup","arguments":"{\"query\":\"tool args text\"}"}}]},
					{"role":"tool","tool_call_id":"call_1","content":"tool result text"}
				],
				"tools":[{"type":"function","function":{"name":"lookup","description":"tool definition text","parameters":{"type":"object","properties":{"query":{"type":"string","description":"schema description text"}}}}}]
			}`,
			want: map[string]string{
				"$.messages[0].content[0].text":                               "chat array text",
				"$.messages[1].tool_calls[0].function.arguments":              `{"query":"tool args text"}`,
				"$.messages[2].content":                                       "tool result text",
				"$.tools[0].function.description":                             "tool definition text",
				"$.tools[0].function.parameters.properties.query.description": "schema description text",
			},
		},
		{
			name: "openai responses",
			path: "/v1/responses",
			body: `{
				"model":"gpt-4o",
				"instructions":"response instructions",
				"input":[
					{"role":"user","content":[{"type":"input_text","text":"input item text"}]},
					{"type":"function_call","name":"lookup","arguments":"{\"zip\":\"tool args\"}"},
					{"type":"function_call_output","call_id":"c","output":"tool output text"}
				],
				"output":[{"type":"message","content":[{"type":"output_text","text":"output item text"}]}],
				"tools":[{"type":"function","name":"lookup","description":"response tool def","parameters":{"type":"object","properties":{"zip":{"type":"string","description":"zip schema"}}}}]
			}`,
			want: map[string]string{
				"$.instructions":                                   "response instructions",
				"$.input[0].content[0].text":                       "input item text",
				"$.input[1].arguments":                             `{"zip":"tool args"}`,
				"$.input[2].output":                                "tool output text",
				"$.output[0].content[0].text":                      "output item text",
				"$.tools[0].description":                           "response tool def",
				"$.tools[0].parameters.properties.zip.description": "zip schema",
			},
		},
		{
			name: "anthropic messages",
			path: "/v1/messages",
			body: `{
				"model":"claude-3-5-sonnet",
				"system":[{"type":"text","text":"system text"}],
				"messages":[
					{"role":"user","content":[{"type":"text","text":"anthropic user text"}]},
					{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"lookup","input":{"query":"anthropic args text"}}]},
					{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"anthropic tool result"}]}]}
				],
				"tools":[{"name":"lookup","description":"anthropic tool definition","input_schema":{"type":"object","properties":{"query":{"type":"string","description":"anthropic schema description"}}}}]
			}`,
			want: map[string]string{
				"$.system[0].text":                                     "system text",
				"$.messages[0].content[0].text":                        "anthropic user text",
				"$.messages[1].content[0].input.query":                 "anthropic args text",
				"$.messages[2].content[0].content[0].text":             "anthropic tool result",
				"$.tools[0].description":                               "anthropic tool definition",
				"$.tools[0].input_schema.properties.query.description": "anthropic schema description",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Extract(tc.path, []byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}

			got := map[string]string{}
			for _, unit := range result.Units {
				got[unit.Path] = unit.Text
			}

			for path, text := range tc.want {
				if got[path] != text {
					t.Fatalf("path %s: expected %q, got %q; all units: %+v", path, text, got[path], result.Units)
				}
			}
		})
	}
}

func TestUnknownTopLevelFieldsAreReturnedAsUnscannedMetadata(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[],"new_provider_text":"not scanned yet"}`)
	result, err := Extract("/v1/chat/completions", body)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.UnscannedFields) != 1 {
		t.Fatalf("expected one unscanned field, got %+v", result.UnscannedFields)
	}
	if result.UnscannedFields[0] != "$.new_provider_text" {
		t.Fatalf("expected unknown field path, got %+v", result.UnscannedFields)
	}
	for _, unit := range result.Units {
		if strings.Contains(unit.Text, "not scanned yet") {
			t.Fatalf("unknown field was scanned instead of being reported: %+v", unit)
		}
	}
}
