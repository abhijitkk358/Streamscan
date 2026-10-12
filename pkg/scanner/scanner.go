// Package scanner finds sensitive data in a byte stream without loading the
// whole stream into memory.
package scanner

import (
	"bytes"
	"io"
	"sort"

	"streamscan/pkg/model"
)

// DefaultChunkSize is used when Options.ChunkSize is zero or negative.
const DefaultChunkSize = 4096

// overlap is how many trailing bytes are carried into the next window. It is
// larger than MaxMatchLen so every match that *starts* in the safe zone is
// fully visible (plus one byte of lookahead for the \b checks).
const overlap = MaxMatchLen + 8

// Options configures a Scanner.
type Options struct {
	ChunkSize      int  // bytes read per iteration (default 4096)
	SkipValidation bool // if true, regex matches are reported without Luhn checks (benchmarking)
}

// Scanner scans streams using a fixed set of detectors.
type Scanner struct {
	dets           []Detector
	chunkSize      int
	skipValidation bool
}

// New creates a Scanner with the default detectors.
func New(opts Options) *Scanner {
	cs := opts.ChunkSize
	if cs <= 0 {
		cs = DefaultChunkSize
	}
	return &Scanner{dets: DefaultDetectors(), chunkSize: cs, skipValidation: opts.SkipValidation}
}

var newline = []byte{'\n'}

// Scan reads r in chunks and calls emit for every finding, in stream order.
// It returns the number of bytes read.
//
// How chunk boundaries are handled: unread data is kept in a window made of
// the carried-over tail plus the new chunk. A match is only reported when it
// starts before len(window)-overlap (the "safe zone"), where it is guaranteed
// to be fully inside the window. Matches starting in the last `overlap` bytes
// are left for the next window, which begins with exactly those bytes. A
// running "consumed" offset stops any text from being reported twice.
func (s *Scanner) Scan(r io.Reader, emit func(model.Finding) error) (int64, error) {
	var (
		chunk      = make([]byte, s.chunkSize)
		buf        []byte
		baseOffset int64                        // absolute offset of buf[0]
		baseLine   = 1                          // line number at buf[0]
		consumed   int64                        // matches starting before this absolute offset are skipped
		next       = make([]int64, len(s.dets)) // per detector: absolute offset where its next regex search begins
		total      int64
		eof        bool
	)
	for !eof {
		n, err := io.ReadFull(r, chunk)
		switch err {
		case nil:
		case io.EOF, io.ErrUnexpectedEOF:
			eof = true
		default:
			return total, err
		}
		total += int64(n)
		buf = append(buf, chunk[:n]...)

		safeEnd := len(buf) - overlap
		if eof {
			safeEnd = len(buf) // final window: nothing more is coming
		}
		if safeEnd <= 0 {
			continue
		}
		if err := s.scanWindow(buf, baseOffset, baseLine, safeEnd, next, &consumed, emit); err != nil {
			return total, err
		}
		if eof {
			break
		}
		// Retire the bytes we are done with. We keep the overlap tail PLUS one
		// already-judged byte in front of it: regexp's \b needs to see the
		// character before a match, otherwise the tail of a longer digit run
		// would look like a standalone number at the start of the new window.
		keep := safeEnd - 1
		baseLine += bytes.Count(buf[:keep], newline)
		baseOffset += int64(keep)
		buf = append(buf[:0], buf[keep:]...)
	}
	return total, nil
}

// ScanAll is a convenience wrapper that collects all findings.
func (s *Scanner) ScanAll(r io.Reader) ([]model.Finding, error) {
	var out []model.Finding
	_, err := s.Scan(r, func(f model.Finding) error { out = append(out, f); return nil })
	return out, err
}

type candidate struct {
	start, end, det int
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// safeCut returns the first index >= from where a regex search can begin
// without changing how \b behaves. regexp treats the start of the slice it is
// given as the start of the text, so we only cut at the true start of the
// stream, or at a position whose previous byte is a non-word character (there
// \b means exactly the same thing with or without the left context).
// This is valid because every detector's match begins with \b followed by a
// word character; no match can start at a position preceded by a word byte.
func safeCut(buf []byte, from int, streamStart bool) int {
	if from <= 0 {
		if streamStart {
			return 0
		}
		from = 1 // buf[0] is the retained context byte, never a search start
	}
	for i := from; i < len(buf); i++ {
		if !isWordByte(buf[i-1]) {
			return i
		}
	}
	return len(buf)
}

func (s *Scanner) scanWindow(buf []byte, baseOffset int64, baseLine, safeEnd int,
	next []int64, consumed *int64, emit func(model.Finding) error) error {

	// 1. Run every detector's regex over the window, resuming each one exactly
	//    where its previous regex match ended. This makes each detector see the
	//    same sequence of matches it would see in a single whole-input scan.
	var cands []candidate
	for di, d := range s.dets {
		from := safeCut(buf, int(next[di]-baseOffset), baseOffset == 0)
		if from >= len(buf) {
			continue
		}
		for _, m := range d.Re.FindAllIndex(buf[from:], -1) {
			start := m[0] + from
			if start >= safeEnd {
				break // matches are ascending; the rest belong to the next window
			}
			end := m[1] + from
			cands = append(cands, candidate{start, end, di})
			next[di] = baseOffset + int64(end)
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].start != cands[j].start {
			return cands[i].start < cands[j].start
		}
		return cands[i].det < cands[j].det
	})

	// 2. Validate (Luhn) and drop candidates overlapping an earlier finding.
	line, prev := baseLine, 0
	for _, c := range cands {
		abs := baseOffset + int64(c.start)
		if abs < *consumed {
			continue // overlaps something already reported
		}
		d := s.dets[c.det]
		validated := false
		if d.Validate != nil && !s.skipValidation {
			if !d.Validate(string(buf[c.start:c.end])) {
				continue
			}
			validated = true
		}
		line += bytes.Count(buf[prev:c.start], newline)
		prev = c.start

		*consumed = baseOffset + int64(c.end)
		if err := emit(model.Finding{
			Type:      d.Name,
			Value:     string(buf[c.start:c.end]),
			Line:      line,
			Offset:    abs,
			Validated: validated,
		}); err != nil {
			return err
		}
	}
	return nil
}
