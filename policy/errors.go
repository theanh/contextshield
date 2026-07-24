package policy

import (
	"encoding/json"
	"strings"
)

type BlockDetail struct {
	Class     string `json:"class"`
	RuleID    string `json:"rule_id"`
	RequestID string `json:"request_id"`
}

type openAIError struct {
	Error openAIErrorBody `json:"error"`
}

type openAIErrorBody struct {
	Message string      `json:"message"`
	Type    string      `json:"type"`
	Code    string      `json:"code"`
	Param   interface{} `json:"param"`
	Detail  BlockDetail `json:"detail"`
}

type anthropicError struct {
	Type  string             `json:"type"`
	Error anthropicErrorBody `json:"error"`
}

type anthropicErrorBody struct {
	Type    string      `json:"type"`
	Message string      `json:"message"`
	Detail  BlockDetail `json:"detail"`
}

// BlockErrorForPath builds the provider-shaped block error body. direction is
// "request" or "response" — applyActions is shared by both the request-side
// scan and the (non-streaming) response-side scan, so the wording must
// reflect which side actually got blocked rather than always claiming
// "request" (the streaming block path, writeStreamBlockEvent, doesn't need
// this parameter: streaming only ever scans responses, so "response" is
// correct there by construction).
func BlockErrorForPath(path, direction string, detail BlockDetail) (int, []byte) {
	// Two literal picks, not a runtime title-case of direction: both provider
	// shapes need a specific casing convention (Anthropic lowercase, OpenAI
	// Title-case) for exactly two known values, and any unexpected direction
	// value defaults to "request"/"Request" — the safe, pre-existing
	// behavior — rather than being baked into the message verbatim or
	// panicking on an empty string.
	lowerVerb, titleVerb := "request", "Request"
	if direction == "response" {
		lowerVerb, titleVerb = "response", "Response"
	}
	if strings.HasSuffix(path, "/v1/messages") {
		body, _ := json.Marshal(anthropicError{
			Type: "error",
			Error: anthropicErrorBody{
				Type:    "contextshield_blocked",
				Message: lowerVerb + " blocked by ContextShield policy",
				Detail:  detail,
			},
		})
		return 403, body
	}
	body, _ := json.Marshal(openAIError{
		Error: openAIErrorBody{
			Message: titleVerb + " blocked by ContextShield policy",
			Type:    "contextshield_blocked",
			Code:    "contextshield_blocked",
			Param:   nil,
			Detail:  detail,
		},
	})
	return 403, body
}
