package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

type Verdict string

const (
	VerdictForwarded Verdict = "forwarded"
	VerdictMasked    Verdict = "masked"
	VerdictBlocked   Verdict = "blocked"
	VerdictExempted  Verdict = "exempted"
	VerdictError     Verdict = "error"
)

type Finding struct {
	Class  string `json:"class"`
	Count  int    `json:"count"`
	Action string `json:"action"`
}

type Entry struct {
	SchemaVersion   string    `json:"schema_version,omitempty"`
	Timestamp       string    `json:"ts"`
	RequestID       string    `json:"req_id"`
	Direction       string    `json:"direction"`
	Caller          string    `json:"caller,omitempty"`
	Dest            string    `json:"dest"`
	Model           string    `json:"model,omitempty"`
	Findings        []Finding `json:"findings"`
	UnscannedFields []string  `json:"unscanned_fields,omitempty"`
	Verdict         Verdict   `json:"verdict"`
	BodySHA         string    `json:"body_sha256"`
	PolicyRev       string    `json:"policy_rev,omitempty"`
}

type Writer struct {
	mu  sync.Mutex
	out io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{out: w}
}

func (lw *Writer) Append(entry Entry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal ledger entry: %w", err)
	}
	lw.mu.Lock()
	_, err = fmt.Fprintln(lw.out, string(data))
	lw.mu.Unlock()
	if err != nil {
		return fmt.Errorf("write ledger entry: %w", err)
	}
	return nil
}

func BodySHA256(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}
