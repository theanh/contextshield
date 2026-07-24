// Package adapter extracts provider-visible text fields from supported model
// API JSON payloads without rewriting the original body bytes.
package adapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type Format string

const (
	FormatUnknown               Format = ""
	FormatOpenAIChatCompletions Format = "openai_chat_completions"
	FormatOpenAIResponses       Format = "openai_responses"
	FormatAnthropicMessages     Format = "anthropic_messages"
)

var ErrUnsupportedPath = errors.New("unsupported provider path")

type Result struct {
	Format          Format
	Units           []ScanUnit
	UnscannedFields []string
}

type ScanUnit struct {
	Path            string
	Kind            string
	Text            string
	RawStart        int
	RawEnd          int
	RawContentStart int
	RawContentEnd   int
	ByteRanges      []ByteRange
}

type ByteRange struct {
	Start int
	End   int
}

func (u ScanUnit) RawSpan(decodedStart, decodedEnd int) (int, int, bool) {
	if decodedStart < 0 || decodedEnd < decodedStart || decodedEnd > len(u.Text) {
		return 0, 0, false
	}
	if decodedStart == decodedEnd || len(u.ByteRanges) != len(u.Text) {
		return 0, 0, false
	}
	return u.ByteRanges[decodedStart].Start, u.ByteRanges[decodedEnd-1].End, true
}

func DetectFormat(path string) Format {
	path = strings.TrimSpace(path)
	if parsed, err := url.Parse(path); err == nil && parsed.Path != "" {
		path = parsed.Path
	}
	if queryAt := strings.IndexByte(path, '?'); queryAt >= 0 {
		path = path[:queryAt]
	}
	path = strings.TrimRight(path, "/")

	switch {
	case strings.HasSuffix(path, "/chat/completions"):
		return FormatOpenAIChatCompletions
	case strings.HasSuffix(path, "/responses"):
		return FormatOpenAIResponses
	case strings.HasSuffix(path, "/messages"):
		return FormatAnthropicMessages
	default:
		return FormatUnknown
	}
}

func Extract(path string, body []byte) (Result, error) {
	format := DetectFormat(path)
	if format == FormatUnknown {
		return Result{Format: format, UnscannedFields: []string{"$"}}, ErrUnsupportedPath
	}

	root, err := parseJSON(body)
	if err != nil {
		return Result{Format: format}, err
	}

	e := newExtractor(format)
	switch format {
	case FormatOpenAIChatCompletions:
		extractOpenAIChat(e, root)
	case FormatOpenAIResponses:
		extractOpenAIResponses(e, root)
	case FormatAnthropicMessages:
		extractAnthropicMessages(e, root)
	}
	return e.result(), nil
}

type extractor struct {
	format    Format
	units     []ScanUnit
	seenUnits map[string]struct{}
	unscanned map[string]struct{}
}

func newExtractor(format Format) *extractor {
	return &extractor{
		format:    format,
		seenUnits: map[string]struct{}{},
		unscanned: map[string]struct{}{},
	}
}

func (e *extractor) result() Result {
	unscanned := make([]string, 0, len(e.unscanned))
	for path := range e.unscanned {
		unscanned = append(unscanned, path)
	}
	sort.Strings(unscanned)
	return Result{
		Format:          e.format,
		Units:           e.units,
		UnscannedFields: unscanned,
	}
}

func (e *extractor) addString(kind, path string, n *jsonNode) {
	if n == nil || n.kind != nodeString || n.stringValue == "" {
		return
	}
	key := fmt.Sprintf("%s:%d:%d", path, n.rawStart, n.rawEnd)
	if _, ok := e.seenUnits[key]; ok {
		return
	}
	e.seenUnits[key] = struct{}{}
	e.units = append(e.units, ScanUnit{
		Path:            path,
		Kind:            kind,
		Text:            n.stringValue,
		RawStart:        n.rawStart,
		RawEnd:          n.rawEnd,
		RawContentStart: n.rawContentStart,
		RawContentEnd:   n.rawContentEnd,
		ByteRanges:      append([]ByteRange(nil), n.byteRanges...),
	})
}

func (e *extractor) addNumber(kind, path string, n *jsonNode) {
	if n == nil || n.kind != nodeNumber || n.stringValue == "" {
		return
	}
	key := fmt.Sprintf("%s:%d:%d", path, n.rawStart, n.rawEnd)
	if _, ok := e.seenUnits[key]; ok {
		return
	}
	e.seenUnits[key] = struct{}{}
	e.units = append(e.units, ScanUnit{
		Path:            path,
		Kind:            kind,
		Text:            n.stringValue,
		RawStart:        n.rawStart,
		RawEnd:          n.rawEnd,
		RawContentStart: n.rawStart,
		RawContentEnd:   n.rawEnd,
		ByteRanges:      append([]ByteRange(nil), n.byteRanges...),
	})
}

func (e *extractor) addStringLeaves(kind, path string, n *jsonNode) {
	if n == nil {
		return
	}
	switch n.kind {
	case nodeString:
		e.addString(kind, path, n)
	case nodeArray:
		for i, child := range n.arrayValues {
			e.addStringLeaves(kind, indexPath(path, i), child)
		}
	case nodeObject:
		for _, member := range n.members {
			e.addStringLeaves(kind, childPath(path, member.key), member.value)
		}
	}
}

func (e *extractor) addScalarLeaves(kind, path string, n *jsonNode) {
	if n == nil {
		return
	}
	switch n.kind {
	case nodeString:
		e.addString(kind, path, n)
	case nodeNumber:
		e.addNumber(kind, path, n)
	case nodeArray:
		for i, child := range n.arrayValues {
			e.addScalarLeaves(kind, indexPath(path, i), child)
		}
	case nodeObject:
		for _, member := range n.members {
			e.addScalarLeaves(kind, childPath(path, member.key), member.value)
		}
	}
}

func (e *extractor) addJSONString(kind, path string, n *jsonNode) {
	e.addString(kind, path, n)
	if n == nil || n.kind != nodeString {
		return
	}
	inner, err := parseJSON([]byte(n.stringValue))
	if err != nil {
		return
	}
	e.addComposedScalarLeaves(kind+"_json", path, inner, n)
}

func (e *extractor) addComposedScalarLeaves(kind, path string, inner, outer *jsonNode) {
	if inner == nil {
		return
	}
	switch inner.kind {
	case nodeString, nodeNumber:
		e.addComposedScalar(kind, path, inner, outer)
	case nodeArray:
		for i, child := range inner.arrayValues {
			e.addComposedScalarLeaves(kind, indexPath(path, i), child, outer)
		}
	case nodeObject:
		for _, member := range inner.members {
			e.addComposedScalarLeaves(kind, childPath(path, member.key), member.value, outer)
		}
	}
}

func (e *extractor) addComposedScalar(kind, path string, inner, outer *jsonNode) {
	if inner.stringValue == "" {
		return
	}
	byteRanges := composeByteRanges(outer.byteRanges, inner.byteRanges)
	rawStart, okStart := composeByteBoundary(outer.byteRanges, inner.rawStart)
	rawEnd, okEnd := composeByteBoundary(outer.byteRanges, inner.rawEnd)
	contentStart, okContentStart := composeByteBoundary(outer.byteRanges, inner.rawContentStart)
	contentEnd, okContentEnd := composeByteBoundary(outer.byteRanges, inner.rawContentEnd)
	if !okStart || !okEnd {
		rawStart = outer.rawStart
		rawEnd = outer.rawEnd
	}
	if !okContentStart || !okContentEnd {
		contentStart = rawStart
		contentEnd = rawEnd
	}

	key := fmt.Sprintf("%s:%d:%d", path, rawStart, rawEnd)
	if _, ok := e.seenUnits[key]; ok {
		return
	}
	e.seenUnits[key] = struct{}{}
	e.units = append(e.units, ScanUnit{
		Path:            path,
		Kind:            kind,
		Text:            inner.stringValue,
		RawStart:        rawStart,
		RawEnd:          rawEnd,
		RawContentStart: contentStart,
		RawContentEnd:   contentEnd,
		ByteRanges:      byteRanges,
	})
}

func (e *extractor) flagUnknownMembers(n *jsonNode, path string, known map[string]struct{}) {
	if n == nil || n.kind != nodeObject {
		return
	}
	for _, member := range n.members {
		if _, ok := known[member.key]; !ok {
			e.unscanned[childPath(path, member.key)] = struct{}{}
		}
	}
}

func extractOpenAIChat(e *extractor, root *jsonNode) {
	e.flagUnknownMembers(root, "$", openAIChatTopLevelFields)

	for _, messages := range memberValues(root, "$", "messages") {
		extractOpenAIChatMessages(e, messages.path, messages.node)
	}
	for _, tools := range memberValues(root, "$", "tools") {
		extractOpenAIChatTools(e, tools.path, tools.node)
	}
	for _, functions := range memberValues(root, "$", "functions") {
		extractOpenAILegacyFunctions(e, functions.path, functions.node)
	}
}

func extractOpenAIChatMessages(e *extractor, path string, n *jsonNode) {
	if n == nil || n.kind != nodeArray {
		return
	}
	for i, message := range n.arrayValues {
		messagePath := indexPath(path, i)
		e.flagUnknownMembers(message, messagePath, openAIChatMessageFields)
		for _, content := range memberValues(message, messagePath, "content") {
			extractOpenAIContent(e, "message_content", content.path, content.node)
		}
		for _, calls := range memberValues(message, messagePath, "tool_calls") {
			extractOpenAIToolCalls(e, calls.path, calls.node)
		}
		for _, call := range memberValues(message, messagePath, "function_call") {
			extractOpenAIFunctionCall(e, call.path, call.node)
		}
	}
}

func extractOpenAIContent(e *extractor, kind, path string, n *jsonNode) {
	if n == nil {
		return
	}
	switch n.kind {
	case nodeString:
		e.addString(kind, path, n)
	case nodeArray:
		for i, part := range n.arrayValues {
			partPath := indexPath(path, i)
			if part.kind == nodeString {
				e.addString(kind, partPath, part)
				continue
			}
			e.flagUnknownMembers(part, partPath, openAIContentPartFields)
			for _, text := range memberValues(part, partPath, "text") {
				e.addString(kind, text.path, text.node)
			}
			for _, text := range memberValues(part, partPath, "input_text") {
				e.addString(kind, text.path, text.node)
			}
			for _, text := range memberValues(part, partPath, "output_text") {
				e.addString(kind, text.path, text.node)
			}
			for _, refusal := range memberValues(part, partPath, "refusal") {
				e.addString(kind, refusal.path, refusal.node)
			}
			for _, imageURL := range memberValues(part, partPath, "image_url") {
				for _, rawURL := range memberValues(imageURL.node, imageURL.path, "url") {
					e.addString("image_url", rawURL.path, rawURL.node)
				}
			}
		}
	}
}

func extractOpenAIToolCalls(e *extractor, path string, n *jsonNode) {
	if n == nil || n.kind != nodeArray {
		return
	}
	for i, call := range n.arrayValues {
		callPath := indexPath(path, i)
		e.flagUnknownMembers(call, callPath, openAIToolCallFields)
		for _, function := range memberValues(call, callPath, "function") {
			extractOpenAIFunctionCall(e, function.path, function.node)
		}
		for _, output := range memberValues(call, callPath, "output") {
			extractToolOutput(e, output.path, output.node)
		}
	}
}

func extractOpenAIFunctionCall(e *extractor, path string, n *jsonNode) {
	e.flagUnknownMembers(n, path, openAIFunctionCallFields)
	for _, arguments := range memberValues(n, path, "arguments") {
		e.addJSONString("tool_arguments", arguments.path, arguments.node)
	}
}

func extractOpenAIChatTools(e *extractor, path string, n *jsonNode) {
	if n == nil || n.kind != nodeArray {
		return
	}
	for i, tool := range n.arrayValues {
		toolPath := indexPath(path, i)
		e.flagUnknownMembers(tool, toolPath, openAIChatToolFields)
		for _, function := range memberValues(tool, toolPath, "function") {
			extractOpenAIFunctionDefinition(e, function.path, function.node, "parameters")
		}
	}
}

func extractOpenAILegacyFunctions(e *extractor, path string, n *jsonNode) {
	if n == nil || n.kind != nodeArray {
		return
	}
	for i, function := range n.arrayValues {
		extractOpenAIFunctionDefinition(e, indexPath(path, i), function, "parameters")
	}
}

func extractOpenAIResponses(e *extractor, root *jsonNode) {
	e.flagUnknownMembers(root, "$", openAIResponsesTopLevelFields)

	for _, instructions := range memberValues(root, "$", "instructions") {
		e.addString("instructions", instructions.path, instructions.node)
	}
	for _, input := range memberValues(root, "$", "input") {
		extractResponsesInputOutput(e, "input", input.path, input.node)
	}
	for _, output := range memberValues(root, "$", "output") {
		extractResponsesInputOutput(e, "output", output.path, output.node)
	}
	for _, tools := range memberValues(root, "$", "tools") {
		extractOpenAIResponseTools(e, tools.path, tools.node)
	}
}

func extractResponsesInputOutput(e *extractor, kind, path string, n *jsonNode) {
	if n == nil {
		return
	}
	switch n.kind {
	case nodeString:
		e.addString(kind, path, n)
	case nodeArray:
		for i, item := range n.arrayValues {
			extractResponseItem(e, indexPath(path, i), item)
		}
	case nodeObject:
		extractResponseItem(e, path, n)
	}
}

func extractResponseItem(e *extractor, path string, n *jsonNode) {
	if n == nil {
		return
	}
	if n.kind == nodeString {
		e.addString("response_item", path, n)
		return
	}
	e.flagUnknownMembers(n, path, openAIResponseItemFields)
	for _, content := range memberValues(n, path, "content") {
		extractOpenAIContent(e, "response_content", content.path, content.node)
	}
	for _, arguments := range memberValues(n, path, "arguments") {
		e.addJSONString("tool_arguments", arguments.path, arguments.node)
	}
	for _, output := range memberValues(n, path, "output") {
		extractToolOutput(e, output.path, output.node)
	}
	for _, code := range memberValues(n, path, "code") {
		e.addString("tool_code", code.path, code.node)
	}
	for _, summary := range memberValues(n, path, "summary") {
		e.addStringLeaves("response_summary", summary.path, summary.node)
	}
	for _, queries := range memberValues(n, path, "queries") {
		e.addStringLeaves("search_query", queries.path, queries.node)
	}
}

func extractOpenAIResponseTools(e *extractor, path string, n *jsonNode) {
	if n == nil || n.kind != nodeArray {
		return
	}
	for i, tool := range n.arrayValues {
		toolPath := indexPath(path, i)
		e.flagUnknownMembers(tool, toolPath, openAIResponseToolFields)
		extractOpenAIFunctionDefinitionText(e, toolPath, tool, "parameters")
	}
}

func extractOpenAIFunctionDefinition(e *extractor, path string, n *jsonNode, schemaKey string) {
	e.flagUnknownMembers(n, path, openAIFunctionDefinitionFields)
	extractOpenAIFunctionDefinitionText(e, path, n, schemaKey)
}

func extractOpenAIFunctionDefinitionText(e *extractor, path string, n *jsonNode, schemaKey string) {
	for _, description := range memberValues(n, path, "description") {
		e.addString("tool_definition", description.path, description.node)
	}
	for _, parameters := range memberValues(n, path, schemaKey) {
		e.addStringLeaves("tool_schema", parameters.path, parameters.node)
	}
}

func extractAnthropicMessages(e *extractor, root *jsonNode) {
	e.flagUnknownMembers(root, "$", anthropicTopLevelFields)

	for _, system := range memberValues(root, "$", "system") {
		extractAnthropicContent(e, "system", system.path, system.node)
	}
	for _, messages := range memberValues(root, "$", "messages") {
		extractAnthropicMessageArray(e, messages.path, messages.node)
	}
	for _, tools := range memberValues(root, "$", "tools") {
		extractAnthropicTools(e, tools.path, tools.node)
	}
}

func extractAnthropicMessageArray(e *extractor, path string, n *jsonNode) {
	if n == nil || n.kind != nodeArray {
		return
	}
	for i, message := range n.arrayValues {
		messagePath := indexPath(path, i)
		e.flagUnknownMembers(message, messagePath, anthropicMessageFields)
		for _, content := range memberValues(message, messagePath, "content") {
			extractAnthropicContent(e, "message_content", content.path, content.node)
		}
	}
}

func extractAnthropicContent(e *extractor, kind, path string, n *jsonNode) {
	if n == nil {
		return
	}
	switch n.kind {
	case nodeString:
		e.addString(kind, path, n)
	case nodeArray:
		for i, block := range n.arrayValues {
			extractAnthropicBlock(e, indexPath(path, i), block)
		}
	case nodeObject:
		extractAnthropicBlock(e, path, n)
	}
}

func extractAnthropicBlock(e *extractor, path string, n *jsonNode) {
	if n == nil {
		return
	}
	if n.kind == nodeString {
		e.addString("message_content", path, n)
		return
	}
	e.flagUnknownMembers(n, path, anthropicBlockFields)

	for _, text := range memberValues(n, path, "text") {
		e.addString("message_content", text.path, text.node)
	}
	for _, thinking := range memberValues(n, path, "thinking") {
		e.addString("thinking", thinking.path, thinking.node)
	}
	for _, title := range memberValues(n, path, "title") {
		e.addString("document_title", title.path, title.node)
	}
	for _, context := range memberValues(n, path, "context") {
		e.addString("document_context", context.path, context.node)
	}
	for _, input := range memberValues(n, path, "input") {
		e.addScalarLeaves("tool_arguments", input.path, input.node)
	}
	for _, content := range memberValues(n, path, "content") {
		extractAnthropicContent(e, "tool_result", content.path, content.node)
	}
	for _, source := range memberValues(n, path, "source") {
		extractAnthropicSource(e, source.path, source.node)
	}
}

func extractAnthropicSource(e *extractor, path string, n *jsonNode) {
	if n == nil || n.kind != nodeObject {
		return
	}
	sourceType := stringMember(n, "type")
	mediaType := stringMember(n, "media_type")
	mimeType := stringMember(n, "mime_type")
	isText := sourceType == "text" || strings.HasPrefix(mediaType, "text/") || strings.HasPrefix(mimeType, "text/")
	if !isText {
		return
	}
	for _, data := range memberValues(n, path, "data") {
		e.addString("document_source", data.path, data.node)
	}
}

func extractAnthropicTools(e *extractor, path string, n *jsonNode) {
	if n == nil || n.kind != nodeArray {
		return
	}
	for i, tool := range n.arrayValues {
		toolPath := indexPath(path, i)
		e.flagUnknownMembers(tool, toolPath, anthropicToolFields)
		for _, description := range memberValues(tool, toolPath, "description") {
			e.addString("tool_definition", description.path, description.node)
		}
		for _, inputSchema := range memberValues(tool, toolPath, "input_schema") {
			e.addStringLeaves("tool_schema", inputSchema.path, inputSchema.node)
		}
	}
}

func extractToolOutput(e *extractor, path string, n *jsonNode) {
	if n == nil {
		return
	}
	if n.kind == nodeString {
		e.addJSONString("tool_result", path, n)
		return
	}
	e.addScalarLeaves("tool_result", path, n)
}

type nodeAtPath struct {
	path string
	node *jsonNode
}

func memberValues(n *jsonNode, path, key string) []nodeAtPath {
	if n == nil || n.kind != nodeObject {
		return nil
	}
	values := []nodeAtPath{}
	for _, member := range n.members {
		if member.key == key {
			values = append(values, nodeAtPath{
				path: childPath(path, key),
				node: member.value,
			})
		}
	}
	return values
}

func stringMember(n *jsonNode, key string) string {
	for _, value := range memberValues(n, "$", key) {
		if value.node.kind == nodeString {
			return value.node.stringValue
		}
	}
	return ""
}

func childPath(base, key string) string {
	if isPathIdentifier(key) {
		return base + "." + key
	}
	return base + "[" + strconv.Quote(key) + "]"
}

func indexPath(base string, index int) string {
	return fmt.Sprintf("%s[%d]", base, index)
}

func isPathIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
				return false
			}
			continue
		}
		if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func fieldSet(fields ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		set[field] = struct{}{}
	}
	return set
}

func composeByteRanges(outer, inner []ByteRange) []ByteRange {
	if len(inner) == 0 {
		return nil
	}
	ranges := make([]ByteRange, 0, len(inner))
	for _, r := range inner {
		if r.Start < 0 || r.End <= r.Start || r.End > len(outer) {
			return nil
		}
		ranges = append(ranges, ByteRange{
			Start: outer[r.Start].Start,
			End:   outer[r.End-1].End,
		})
	}
	return ranges
}

func composeByteBoundary(outer []ByteRange, offset int) (int, bool) {
	if len(outer) == 0 || offset < 0 || offset > len(outer) {
		return 0, false
	}
	if offset == len(outer) {
		return outer[len(outer)-1].End, true
	}
	return outer[offset].Start, true
}

var openAIChatTopLevelFields = fieldSet(
	"audio",
	"frequency_penalty",
	"function_call",
	"functions",
	"logit_bias",
	"logprobs",
	"max_completion_tokens",
	"max_tokens",
	"metadata",
	"modalities",
	"model",
	"n",
	"parallel_tool_calls",
	"prediction",
	"presence_penalty",
	"reasoning_effort",
	"response_format",
	"seed",
	"service_tier",
	"stop",
	"store",
	"stream",
	"stream_options",
	"temperature",
	"tool_choice",
	"tools",
	"top_logprobs",
	"top_p",
	"user",
	"verbosity",
	"web_search_options",
	"messages",
)

var openAIChatMessageFields = fieldSet(
	"annotations",
	"audio",
	"content",
	"function_call",
	"id",
	"name",
	"refusal",
	"role",
	"tool_call_id",
	"tool_calls",
)

var openAIContentPartFields = fieldSet(
	"annotations",
	"detail",
	"image_file",
	"image_url",
	"input_audio",
	"input_file",
	"input_image",
	"input_text",
	"output_text",
	"refusal",
	"source",
	"text",
	"type",
)

var openAIToolCallFields = fieldSet(
	"function",
	"id",
	"index",
	"output",
	"type",
)

var openAIFunctionCallFields = fieldSet(
	"arguments",
	"name",
)

var openAIChatToolFields = fieldSet(
	"function",
	"type",
)

var openAIFunctionDefinitionFields = fieldSet(
	"description",
	"name",
	"parameters",
	"strict",
)

var openAIResponsesTopLevelFields = fieldSet(
	"background",
	"include",
	"input",
	"instructions",
	"max_output_tokens",
	"metadata",
	"model",
	"output",
	"parallel_tool_calls",
	"previous_response_id",
	"prompt",
	"reasoning",
	"safety_identifier",
	"service_tier",
	"store",
	"stream",
	"stream_options",
	"temperature",
	"text",
	"tool_choice",
	"tools",
	"top_p",
	"truncation",
	"user",
)

var openAIResponseItemFields = fieldSet(
	"action",
	"arguments",
	"call_id",
	"code",
	"container_id",
	"content",
	"encrypted_content",
	"id",
	"name",
	"output",
	"queries",
	"results",
	"role",
	"server_label",
	"status",
	"summary",
	"type",
	"tools",
)

var openAIResponseToolFields = fieldSet(
	"allowed_tools",
	"container",
	"description",
	"filters",
	"name",
	"parameters",
	"server_label",
	"strict",
	"type",
	"vector_store_ids",
)

var anthropicTopLevelFields = fieldSet(
	"container",
	"context_management",
	"max_tokens",
	"mcp_servers",
	"messages",
	"metadata",
	"model",
	"service_tier",
	"stop_sequences",
	"stream",
	"system",
	"temperature",
	"thinking",
	"tool_choice",
	"tools",
	"top_k",
	"top_p",
)

var anthropicMessageFields = fieldSet(
	"content",
	"role",
)

var anthropicBlockFields = fieldSet(
	"cache_control",
	"citations",
	"content",
	"context",
	"data",
	"id",
	"input",
	"is_error",
	"media_type",
	"mime_type",
	"name",
	"signature",
	"source",
	"text",
	"thinking",
	"title",
	"tool_use_id",
	"type",
)

var anthropicToolFields = fieldSet(
	"cache_control",
	"description",
	"input_schema",
	"name",
	"type",
)

type nodeKind int

const (
	nodeObject nodeKind = iota
	nodeArray
	nodeString
	nodeNumber
	nodeBool
	nodeNull
)

type jsonNode struct {
	kind            nodeKind
	rawStart        int
	rawEnd          int
	rawContentStart int
	rawContentEnd   int
	stringValue     string
	byteRanges      []ByteRange
	members         []jsonMember
	arrayValues     []*jsonNode
}

type jsonMember struct {
	key   string
	value *jsonNode
}

type jsonParser struct {
	data []byte
	pos  int
}

func parseJSON(data []byte) (*jsonNode, error) {
	if !json.Valid(data) {
		return nil, fmt.Errorf("parse json: invalid JSON")
	}
	p := &jsonParser{data: data}
	node, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	p.skipWhitespace()
	if p.pos != len(data) {
		return nil, fmt.Errorf("parse json: trailing data at byte %d", p.pos)
	}
	return node, nil
}

func (p *jsonParser) parseValue() (*jsonNode, error) {
	p.skipWhitespace()
	if p.pos >= len(p.data) {
		return nil, fmt.Errorf("parse json: unexpected end")
	}
	switch p.data[p.pos] {
	case '{':
		return p.parseObject()
	case '[':
		return p.parseArray()
	case '"':
		return p.parseString()
	case 't':
		return p.parseLiteral("true", nodeBool)
	case 'f':
		return p.parseLiteral("false", nodeBool)
	case 'n':
		return p.parseLiteral("null", nodeNull)
	default:
		return p.parseNumber()
	}
}

func (p *jsonParser) parseObject() (*jsonNode, error) {
	start := p.pos
	p.pos++
	node := &jsonNode{kind: nodeObject, rawStart: start}
	p.skipWhitespace()
	if p.consume('}') {
		node.rawEnd = p.pos
		return node, nil
	}
	for {
		p.skipWhitespace()
		key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		p.skipWhitespace()
		if !p.consume(':') {
			return nil, fmt.Errorf("parse json: expected ':' at byte %d", p.pos)
		}
		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		node.members = append(node.members, jsonMember{key: key.stringValue, value: value})
		p.skipWhitespace()
		if p.consume('}') {
			node.rawEnd = p.pos
			return node, nil
		}
		if !p.consume(',') {
			return nil, fmt.Errorf("parse json: expected ',' at byte %d", p.pos)
		}
	}
}

func (p *jsonParser) parseArray() (*jsonNode, error) {
	start := p.pos
	p.pos++
	node := &jsonNode{kind: nodeArray, rawStart: start}
	p.skipWhitespace()
	if p.consume(']') {
		node.rawEnd = p.pos
		return node, nil
	}
	for {
		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		node.arrayValues = append(node.arrayValues, value)
		p.skipWhitespace()
		if p.consume(']') {
			node.rawEnd = p.pos
			return node, nil
		}
		if !p.consume(',') {
			return nil, fmt.Errorf("parse json: expected ',' at byte %d", p.pos)
		}
	}
}

func (p *jsonParser) parseString() (*jsonNode, error) {
	start := p.pos
	p.pos++
	contentStart := p.pos
	out := []byte{}
	ranges := []ByteRange{}

	for p.pos < len(p.data) && p.data[p.pos] != '"' {
		rawStart := p.pos
		rest := string(p.data[p.pos:])
		value, _, tail, err := strconv.UnquoteChar(rest, '"')
		if err != nil {
			return nil, fmt.Errorf("parse json string at byte %d: %w", p.pos, err)
		}
		consumed := len(rest) - len(tail)
		encoded := []byte(string(value))
		if p.data[rawStart] != '\\' && consumed == len(encoded) {
			for i := range encoded {
				ranges = append(ranges, ByteRange{Start: rawStart + i, End: rawStart + i + 1})
			}
		} else {
			for range encoded {
				ranges = append(ranges, ByteRange{Start: rawStart, End: rawStart + consumed})
			}
		}
		out = append(out, encoded...)
		p.pos += consumed
	}
	if p.pos >= len(p.data) {
		return nil, fmt.Errorf("parse json: unterminated string at byte %d", start)
	}
	contentEnd := p.pos
	p.pos++
	return &jsonNode{
		kind:            nodeString,
		rawStart:        start,
		rawEnd:          p.pos,
		rawContentStart: contentStart,
		rawContentEnd:   contentEnd,
		stringValue:     string(out),
		byteRanges:      ranges,
	}, nil
}

func (p *jsonParser) parseLiteral(literal string, kind nodeKind) (*jsonNode, error) {
	start := p.pos
	if !strings.HasPrefix(string(p.data[p.pos:]), literal) {
		return nil, fmt.Errorf("parse json: expected %q at byte %d", literal, p.pos)
	}
	p.pos += len(literal)
	return &jsonNode{kind: kind, rawStart: start, rawEnd: p.pos}, nil
}

func (p *jsonParser) parseNumber() (*jsonNode, error) {
	start := p.pos
	for p.pos < len(p.data) && !isValueDelimiter(p.data[p.pos]) {
		p.pos++
	}
	if start == p.pos {
		return nil, fmt.Errorf("parse json: expected value at byte %d", p.pos)
	}
	ranges := make([]ByteRange, 0, p.pos-start)
	for i := start; i < p.pos; i++ {
		ranges = append(ranges, ByteRange{Start: i, End: i + 1})
	}
	return &jsonNode{
		kind:            nodeNumber,
		rawStart:        start,
		rawEnd:          p.pos,
		rawContentStart: start,
		rawContentEnd:   p.pos,
		stringValue:     string(p.data[start:p.pos]),
		byteRanges:      ranges,
	}, nil
}

func (p *jsonParser) skipWhitespace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\n', '\r', '\t':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsonParser) consume(ch byte) bool {
	if p.pos < len(p.data) && p.data[p.pos] == ch {
		p.pos++
		return true
	}
	return false
}

func isValueDelimiter(ch byte) bool {
	switch ch {
	case ' ', '\n', '\r', '\t', ',', '}', ']':
		return true
	default:
		return false
	}
}
