package scanner

import "regexp"

// MaxMatchLen is an upper bound on the length of any single match produced by
// the default detectors. The streaming scanner keeps this many bytes of overlap
// between chunks, which is what guarantees that a secret split across a chunk
// boundary is still found. If you add a detector, keep its matches bounded
// and keep this constant >= the longest possible match.
//
// Second invariant: every detector regex must begin with \b followed by a word
// character (see safeCut in scanner.go). Break that and chunked scanning can
// differ from whole-input scanning.
const MaxMatchLen = 200

// Detector pairs a regex with an optional validator.
type Detector struct {
	Name     string
	Re       *regexp.Regexp
	Validate func(match string) bool // nil means "regex match is enough"
}

var (
	// CardRegex matches 13-19 digit card numbers in contiguous form, or in the
	// common grouped forms (4-4-4-x with spaces or hyphens, and Amex 4-6-5).
	// Candidates still need to pass the Luhn check to become findings.
	CardRegex = regexp.MustCompile(
		`\b(?:\d{13,19}|\d{4}-\d{4}-\d{4}-\d{1,7}|\d{4} \d{4} \d{4} \d{1,7}|\d{4}[ -]\d{6}[ -]\d{5})\b`)

	awsKeyRegex = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)

	// Optional name prefix (so api_token, GITHUB_TOKEN, client_secret match),
	// a keyword, a separator, then a 20-128 character token-looking value.
	// Prefix, whitespace and value length are all bounded so MaxMatchLen holds:
	// 32 + 12 + 1 + 8 + 1 + 8 + 1 + 128 = 191.
	tokenRegex = regexp.MustCompile(
		`(?i)\b[a-z0-9_]{0,32}(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|token)\b["']?[ \t]{0,8}[:=][ \t]{0,8}["']?[A-Za-z0-9_\-./+]{20,128}`)
)

// DefaultDetectors returns the built-in detectors.
func DefaultDetectors() []Detector {
	return []Detector{
		{Name: "credit_card", Re: CardRegex, Validate: func(s string) bool { return LuhnValid(s) }},
		{Name: "aws_access_key", Re: awsKeyRegex},
		{Name: "api_token", Re: tokenRegex},
	}
}

// LuhnValid reports whether s (digits, optionally with spaces or hyphens) has
// 13-19 digits and passes the Luhn checksum. It accepts string or []byte so
// callers can avoid a conversion allocation.
func LuhnValid[T ~string | ~[]byte](s T) bool {
	sum, digits := 0, 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c == ' ' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
		digits++
	}
	return digits >= 13 && digits <= 19 && sum%10 == 0
}
