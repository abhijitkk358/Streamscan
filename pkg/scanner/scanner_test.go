package scanner

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"streamscan/pkg/model"
)

const (
	validVisa = "4111111111111111"
	validMC   = "5500005555555559"
	validAmex = "378282246310005"
	badCard   = "4111111111111112" // fails Luhn
	awsKey    = "AKIAIOSFODNN7EXAMPLE"
)

func TestLuhnValid(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{validVisa, true},
		{validMC, true},
		{validAmex, true},
		{"4111 1111 1111 1111", true},
		{"4111-1111-1111-1111", true},
		{badCard, false},
		{"123", false},                  // too short
		{"41111111111111111111", false}, // 20 digits: too long
		{"4111x11111111111", false},     // non-digit
	}
	for _, tc := range tests {
		if got := LuhnValid(tc.in); got != tc.want {
			t.Errorf("LuhnValid(%q) = %v, want %v", tc.in, got, tc.want)
		}
		if got := LuhnValid([]byte(tc.in)); got != tc.want {
			t.Errorf("LuhnValid([]byte(%q)) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func scan(t *testing.T, chunk int, data string) []model.Finding {
	t.Helper()
	got, err := New(Options{ChunkSize: chunk}).ScanAll(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestDetectors(t *testing.T) {
	data := "card " + validVisa + " ok\n" +
		"grouped 4111 1111 1111 1111 and amex 3782 822463 10005\n" +
		"not a card " + badCard + "\n" +
		"key " + awsKey + "\n" +
		"api_key = \"abcdEFGH1234567890abcdEFGH\"\n" +
		"export GITHUB_TOKEN=ghp_abcdEFGH1234567890abcdEFGH\n" +
		"api_token=\"abcdEFGH1234567890abcdEFGH\"\n" +
		"client_secret: zzzzzzzzzz1111111111yyyyyyyy\n" +
		"token=short\n" // too short to be a token: must NOT match
	got := scan(t, 4096, data)

	var types []string
	for _, f := range got {
		types = append(types, f.Type)
	}
	want := []string{"credit_card", "credit_card", "credit_card", "aws_access_key",
		"api_token", "api_token", "api_token", "api_token"}
	if fmt.Sprint(types) != fmt.Sprint(want) {
		t.Fatalf("types = %v, want %v\nfindings: %+v", types, want, got)
	}
	for _, f := range got {
		if f.Type == "credit_card" && !f.Validated {
			t.Errorf("card finding should be Luhn-validated: %+v", f)
		}
	}
	// Line numbers
	if got[0].Line != 1 || got[1].Line != 2 || got[3].Line != 4 || got[4].Line != 5 {
		t.Errorf("unexpected line numbers: %+v", got)
	}
}

func TestInvalidLuhnIsRejected(t *testing.T) {
	if got := scan(t, 4096, "number: "+badCard); len(got) != 0 {
		t.Fatalf("expected no findings, got %+v", got)
	}
	// Without validation the same input is a (false-positive) match.
	got, _ := New(Options{SkipValidation: true}).ScanAll(strings.NewReader("number: " + badCard))
	if len(got) != 1 {
		t.Fatalf("SkipValidation should report the raw regex match, got %+v", got)
	}
}

// The headline test: a secret must be found exactly once no matter where the
// chunk boundaries fall relative to it. We slide the secret across every
// position in a stream much longer than the overlap, so it straddles the
// "retire" boundary in many different ways, for several chunk sizes.
func TestSecretSplitAcrossChunkBoundaries(t *testing.T) {
	secrets := []struct{ typ, text string }{
		{"credit_card", validVisa},
		{"credit_card", "4111 1111 1111 1111"},
		{"credit_card", "3782 822463 10005"},
		{"aws_access_key", awsKey},
		{"api_token", "token=abcdEFGH1234567890abcdEFGH"},
	}
	filler := strings.Repeat("lorem ipsum dolor sit amet. ", 22) // ~616 bytes
	for _, sec := range secrets {
		step := 1
		if testing.Short() {
			step = 7 // `go test -short` (e.g. with -race) samples fewer alignments
		}
		for pad := 0; pad < 360; pad += step {
			data := filler[:pad] + " " + sec.text + " " + filler
			for _, chunk := range []int{13, 64, 173, 4096} {
				got := scan(t, chunk, data)
				if len(got) != 1 || got[0].Type != sec.typ || got[0].Value != sec.text ||
					got[0].Offset != int64(pad+1) {
					t.Fatalf("secret %q pad=%d chunk=%d: got %+v", sec.text, pad, chunk, got)
				}
			}
		}
	}
}

// Chunked scanning must give exactly the same findings (including offsets and
// line numbers) as scanning the whole input in one window.
func TestChunkedMatchesWholeInput(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	pieces := []string{
		validVisa, validMC, validAmex, "4111 1111 1111 1111", badCard, awsKey,
		"token=abcdEFGH1234567890abcdEFGH", "secret: \"zzzzzzzzzz1111111111yyyyyyyy\"",
		"12345", "hello world", "2024-01-02T03:04:05Z", "\n", "\n", "  ",
		"9999999999999999999999", "AKIA", "api_key=short",
	}
	var sb strings.Builder
	for i := 0; i < 600; i++ {
		sb.WriteString(pieces[rng.Intn(len(pieces))])
		if rng.Intn(3) > 0 {
			sb.WriteByte(' ')
		}
	}
	data := sb.String()
	want := scan(t, len(data)+1, data) // single window
	if len(want) < 20 {
		t.Fatalf("test input too weak: only %d findings", len(want))
	}
	for _, chunk := range []int{1, 2, 3, 5, 7, 13, 64, 100, 255, 256, 1000, 4096} {
		got := scan(t, chunk, data)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("chunk=%d: findings differ from whole-input scan\n got: %d findings\nwant: %d findings", chunk, len(got), len(want))
		}
	}
}

func TestEmptyAndTinyInput(t *testing.T) {
	for _, in := range []string{"", "a", "\n"} {
		if got := scan(t, 4096, in); len(got) != 0 {
			t.Errorf("input %q: unexpected findings %+v", in, got)
		}
	}
}

func TestEmitErrorStopsScan(t *testing.T) {
	data := strings.Repeat(validVisa+"\n", 10)
	calls := 0
	_, err := New(Options{}).Scan(strings.NewReader(data), func(model.Finding) error {
		calls++
		return fmt.Errorf("stop")
	})
	if err == nil || calls != 1 {
		t.Fatalf("expected scan to stop after first emit error, calls=%d err=%v", calls, err)
	}
}

func TestBytesScanned(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 10000)
	n, err := New(Options{ChunkSize: 333}).Scan(bytes.NewReader(data), func(model.Finding) error { return nil })
	if err != nil || n != 10000 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}
