package scanner

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"streamscan/pkg/model"
)

var benchWords = []string{
	"the", "quick", "request", "payload", "user", "session", "server", "error",
	"timeout", "upload", "report", "invoice", "customer", "order", "status",
	"retry", "gateway", "cache", "login", "export",
}

var benchValidCards = []string{
	"4111111111111111", "5500005555555559", "378282246310005", "4012888888881881",
	"4111 1111 1111 1111", "5105-1051-0510-5100",
}

// synthStream builds a deterministic, log-like stream of about `size` bytes.
// Roughly: a valid card every 20 lines, a Luhn-invalid 16-digit number every 7
// lines (the false-positive bait), an AWS key every 50 lines and a token every
// 40 lines. Same seed -> same bytes, so runs are comparable.
func synthStream(size int, seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	var b bytes.Buffer
	b.Grow(size + 256)
	for line := 1; b.Len() < size; line++ {
		for i := 0; i < 6+rng.Intn(8); i++ {
			b.WriteString(benchWords[rng.Intn(len(benchWords))])
			b.WriteByte(' ')
		}
		if line%20 == 0 {
			fmt.Fprintf(&b, "card=%s ", benchValidCards[rng.Intn(len(benchValidCards))])
		}
		if line%7 == 0 {
			// 16 random digits that (almost always) fail Luhn.
			fmt.Fprintf(&b, "ref=%016d ", rng.Int63n(1e16))
		}
		if line%50 == 0 {
			b.WriteString("key=AKIAIOSFODNN7EXAMPLE ")
		}
		if line%40 == 0 {
			b.WriteString("api_token=abcdEFGH1234567890abcdEFGH ")
		}
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// BenchmarkScanThroughput measures end-to-end streaming scan speed (all
// detectors, Luhn on) over 1 MB and 10 MB synthetic streams.
func BenchmarkScanThroughput(b *testing.B) {
	for _, tc := range []struct {
		name string
		size int
	}{{"1MB", 1 << 20}, {"10MB", 10 << 20}} {
		data := synthStream(tc.size, 1)
		b.Run(tc.name, func(b *testing.B) {
			s := New(Options{ChunkSize: DefaultChunkSize})
			var found int
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				found = 0
				if _, err := s.Scan(bytes.NewReader(data), func(model.Finding) error { found++; return nil }); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(found), "findings")
		})
	}
}

// BenchmarkRegexVsLuhn isolates what the Luhn check costs.
//
//	card_regex_only      - just CardRegex.FindAllIndex (every candidate counted)
//	card_regex_plus_luhn - same, then LuhnValid on each candidate
//	scanner_no_luhn      - full scanner, all detectors, validation skipped
//	scanner_with_luhn    - full scanner, all detectors, validation on
//
// The "findings" metric shows the other half of the story: how many
// candidates survive. Without Luhn every random 16-digit number is a hit.
func BenchmarkRegexVsLuhn(b *testing.B) {
	data := synthStream(1<<20, 1)

	b.Run("card_regex_only", func(b *testing.B) {
		var found int
		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			found = len(CardRegex.FindAllIndex(data, -1))
		}
		b.ReportMetric(float64(found), "findings")
	})

	b.Run("card_regex_plus_luhn", func(b *testing.B) {
		var found int
		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			found = 0
			for _, m := range CardRegex.FindAllIndex(data, -1) {
				if LuhnValid(data[m[0]:m[1]]) {
					found++
				}
			}
		}
		b.ReportMetric(float64(found), "findings")
	})

	for _, tc := range []struct {
		name string
		skip bool
	}{{"scanner_no_luhn", true}, {"scanner_with_luhn", false}} {
		b.Run(tc.name, func(b *testing.B) {
			s := New(Options{ChunkSize: DefaultChunkSize, SkipValidation: tc.skip})
			var found int
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				found = 0
				if _, err := s.Scan(bytes.NewReader(data), func(model.Finding) error { found++; return nil }); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(found), "findings")
		})
	}
}
