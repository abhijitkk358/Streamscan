// Package model holds the types shared by the scanner and the crypto layer.
package model

// Finding is one piece of sensitive data detected in a stream.
type Finding struct {
	Type      string `json:"type"`      // e.g. "credit_card", "aws_access_key", "api_token"
	Value     string `json:"value"`     // the plaintext secret (never stored unencrypted)
	Line      int    `json:"line"`      // 1-based line number where the match starts
	Offset    int64  `json:"offset"`    // absolute byte offset where the match starts
	Validated bool   `json:"validated"` // true if a checksum (Luhn) confirmed the match
}
