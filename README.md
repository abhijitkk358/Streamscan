# StreamScan

A streaming sensitive-data scanner in Go (standard library only) whose findings
are **never stored in plaintext**: each one is envelope-encrypted, and a keyed
blind index lets you count duplicates without decrypting anything.

```
cmd/streamscan/        CLI: scan -> encrypted JSON report; --decrypt -> audit
pkg/model/             Finding type
pkg/scanner/           chunked scanner, detectors (card+Luhn, AWS key, token)
pkg/crypto/            envelope encryption (AES-256-GCM) + HMAC blind index
```

## Quick start

```bash
go build -o streamscan ./cmd/streamscan

KEK=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')   # 64 hex chars
./streamscan --file demo.txt --kek $KEK > report.json        # no plaintext inside
./streamscan --decrypt --file report.json --kek $KEK         # audit view (plaintext!)

cat demo.txt | ./streamscan          # stdin; prints an EPHEMERAL demo key to stderr
```

Flags: `--file`, `--chunk-size` (default 4096), `--kek` (hex), `--decrypt`.

## Tests and benchmarks

```bash
go test ./...                 # full suite (~5 s)
go test -race -short ./...    # race detector; -short samples fewer chunk alignments
go test -run '^$' -bench . -benchmem ./pkg/scanner/
```

## How it works

**Scanner.** Reads the stream in chunks. A match is reported only if it starts
in the "safe zone" (`len(window) - overlap`), where it is guaranteed to lie
fully inside the window; the last `overlap` bytes carry into the next window.
`overlap` (208) exceeds the longest possible match (`MaxMatchLen` = 200).
Candidates then pass Luhn (cards) and de-overlap across detectors.

**Crypto.** Per finding: random 32-byte DEK -> AES-256-GCM encrypts the JSON
finding (fresh 12-byte nonce) -> the KEK wraps the DEK (fresh nonce). AAD binds
the wrap to its purpose and the payload to the record's blind index. The blind
index key is derived from the KEK (key separation).

## Bugs found while building (and what fixed them)

1. **`\b` at window edges.** `regexp` treats the start of a slice as the start
   of the text, so cutting a window mid-digit-run made the tail of a longer
   number look like a standalone card. Fix: only start searches at the true
   stream start or just after a non-word byte, and resume each detector where
   its own previous match ended. Caught by comparing chunked vs whole-input
   scans at chunk sizes 1..4096.
2. **Missed `api_token=` / `GITHUB_TOKEN=`.** `\b` before the keyword fails
   after `_`. Fix: bounded optional name prefix. Found by running the CLI on a
   realistic demo file, not by the original unit tests.

## Measured results (sandbox: 1 vCPU Xeon @ 2.1 GHz, Go 1.22, 3 runs each)

| Benchmark | Throughput | Allocs/op | Findings |
|---|---|---|---|
| Full scan, 1 MB | ~5.0 MB/s | 12.3k | 1,799 |
| Full scan, 10 MB | ~5.2 MB/s | 123k | 18,155 |
| Card regex only | ~36-38 MB/s | 3,218 | 3,207 candidates |
| Card regex + Luhn | ~35-36 MB/s | 3,218 | 1,052 valid |
| Scanner, Luhn skipped | ~5 MB/s | 11.2k | 3,954 |
| Scanner, Luhn on | ~5.5 MB/s | 12.3k | 1,799 |

Per-detector regex speed on the same 1 MB: card ~32 MB/s, AWS key ~31 MB/s,
**token ~8 MB/s**, which dominates total cost.

- **Luhn costs almost nothing** (same allocations, difference within noise) but
  removes ~67% of card candidates on this data. The synthetic stream is
  deliberately full of 16-digit non-card numbers, so that ratio is *not* a
  real-world false-positive rate.
- Numbers come from a shared sandbox VM and 3 short runs; rerun with
  `-count=10` and `benchstat` on your own machine before quoting them.

## Limitations (read before trusting it)

- **Slow by design choice**: Go's `regexp` is linear-time but not fast. Next
  steps: a literal prefilter before the token regex, or an Aho-Corasick
  keyword pass.
- Regex detectors only: no context, no file-type parsing, no exact-data
  matching. Tokens longer than 128 chars are truncated; the generic token
  pattern will have real-world false positives and misses.
- Card detection requires contiguous digits or 4-4-4-x / 4-6-5 grouping.
- **Crypto is unaudited.** The KEK comes from a flag/env, which leaks via
  shell history and `ps`; production would use a KMS/HSM. `--decrypt` prints
  full plaintext secrets.
- Random 96-bit GCM nonces under one key are safe only up to about 2^32
  invocations (NIST SP 800-38D). Here the KEK wraps one DEK per finding, so
  that is the cap on findings per KEK; each DEK encrypts exactly one payload.
- Rotating the KEK changes all blind indexes (the index key is derived from it).
- The nonce test is a tripwire for bugs (constant nonce, reused buffer), not a
  proof of uniqueness; the guarantee is the birthday bound above.
- The report is held in memory before being written.
