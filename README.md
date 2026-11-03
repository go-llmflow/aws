# go-llmflow/aws

AWS Signature Version 4 request signing and AWS event-stream decoding, in pure
Go, **standard library only** (no aws-sdk-go, no cgo). Two generic packages, no
service-specific code. They are used by the
[gateway](https://github.com/go-llmflow/gateway)'s Amazon Bedrock provider since
[gateway v0.23.0](https://github.com/go-llmflow/gateway/releases/tag/v0.23.0)
([#89](https://github.com/go-llmflow/gateway/issues/89)).

| package | what |
|---|---|
| `github.com/go-llmflow/aws/sigv4` | sign an `*http.Request` with SigV4 (`Authorization` header) |
| `github.com/go-llmflow/aws/eventstream` | decode the `application/vnd.amazon.eventstream` framing; an encoder for tests and tools |

Status: [v0.1.0](https://github.com/go-llmflow/aws/releases/tag/v0.1.0), the
first release (below v1.0.0, a breaking change bumps the minor version).

## Sources

Opened and followed, not paraphrased from memory:

- SigV4: [Create a signed AWS API request](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)
  (canonical request, `UriEncode`, string to sign, signing key, `Authorization` header).
- SigV4 test vectors: [awslabs/aws-c-auth `tests/aws-signing-test-suite/v4`](https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4)
  at commit `3d29adc`, vendored in `sigv4/testdata/` with its Apache-2.0 licence
  and a `NOTICE`.
- Event stream: the "Event stream encoding" section of
  [Amazon Transcribe streaming](https://docs.aws.amazon.com/transcribe/latest/dg/streaming-setting-up.html)
  and the reference implementation
  [aws-sdk-go-v2 `aws/protocol/eventstream`](https://github.com/aws/aws-sdk-go-v2/tree/main/aws/protocol/eventstream)
  (`message.go`, `header_value.go`, `decode.go`, `encode.go`).

## sigv4

```go
s := sigv4.Signer{
    Credentials: sigv4.Credentials{AccessKeyID: id, SecretAccessKey: secret, SessionToken: tok},
    Region:      "us-east-1",
    Service:     "bedrock",
}
req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
req.Header.Set("Content-Type", "application/json")
err := s.Sign(req, body, time.Now()) // sets X-Amz-Date, X-Amz-Security-Token (if any), Authorization
```

- `Sign(req, body, now)`: the body is only hashed; `req.Body` is not read. Calling it again replaces
  what it set. On error the request is left as it was.
- `Signer.CanonicalRequest(req, body)` and `StringToSign(t, scope, canonical)` are exported for tests
  and debugging; `Signer.Scope(t)` gives the credential scope.
- Every header on the request is signed except `sigv4.UnsignedHeaders` (hop-by-hop headers,
  `User-Agent`, `X-Amzn-Trace-Id`, `Expect`, `Authorization`, ...). `host` (`req.Host`, else
  `req.URL.Host`, which is what `net/http` sends) is always signed.
- An `X-Amz-Content-Sha256` header, if present (e.g. `UNSIGNED-PAYLOAD`), supplies the payload hash.
- Canonical URI: built from the **wire** path (`URL.EscapedPath()`); services other than S3 encode it
  once more and normalise it (dot segments, repeated slashes); service `s3` uses it as is.
  `Signer.DisableNormalize` keeps the path unnormalised. A `+` in the query is a space.
- Header-based signing only; presigned URLs and SigV4a are not implemented.

## eventstream

```go
d := eventstream.NewDecoder(resp.Body, eventstream.Limits{}) // zero fields take the defaults
for {
    m, err := d.Next()           // *Message{Headers []Header; Payload []byte}
    if err == io.EOF { break }   // clean end, at a message boundary
    if err != nil { return err } // io.ErrUnexpectedEOF mid-message; errors.Is(err, eventstream.ErrLength) ...
    v, _ := m.Header(":event-type")
    fmt.Println(v.Str(), len(m.Payload))
}
```

- `Value` is typed: `Bool Int8 Int16 Int32 Int64 Bytes String Timestamp UUID`, with accessors
  (`Str`, `Int`, `Bool`, `Bytes`, `Time`, `UUID`), `Type()` and `String()`.
- `Marshal(Message) ([]byte, error)` / `Encode(w, Message)` are for tests and tools; they reject
  what the decoder rejects.
- After an error other than `io.EOF` the stream is desynchronised; `Next` keeps returning that error.
- Returned messages and payloads are owned by the caller (fresh per message).

### Limits (defaults)

| field | default |
|---|---|
| `MaxMessage` | 16 MiB |
| `MaxHeadersLen` | 128 KiB |
| `MaxHeaders` | 256 |
| `MaxValueLen` | 32767 (also the maximum accepted) |

Checks, in this order: prelude bounds (`total >= 16`, `total >= headers_len + 16`, `total <=
MaxMessage`, `headers_len <= MaxHeadersLen`), then the **prelude CRC before anything is read or
allocated**, then the header block (it must parse exactly to `headers_len`: no duplicate name, no
unknown type, no empty name, strings are valid UTF-8, nothing runs past `headers_len`, at most
`MaxHeaders`), then the message CRC. The body buffer grows with the bytes actually received, so a
peer announcing 16 MiB and sending nothing costs nothing.

**A defect of the reference, not repeated here.** In aws-sdk-go-v2, `ValidateLens` only rejects
`Length == 0`, and `PayloadLen() = Length - HeadersLen - 16` underflows a `uint32` when
`Length < HeadersLen + 16`. This decoder rejects that case (`ErrLength`), with a planted test.

**A typo in the Transcribe page.** The first base64 example of the "Event stream encoding" section is
corrupted as printed (four bytes of the header names, `7#ontent-type` and `Conzent-Type`). The test
suite pins that it is rejected as printed and that, with those four bytes repaired, it decodes under
the page's own CRC to the headers the page states. The second example (`:date`, `:chunk-signature`)
decodes as printed and re-encodes byte for byte.

## Test vectors and their licence

`sigv4/testdata/v4/` holds the 38 cases of the aws-c-auth v4 suite (`request.txt`, `context.json`,
`header-canonical-request.txt`, `header-string-to-sign.txt`, `header-signature.txt`), under the
Apache License 2.0 (`sigv4/testdata/LICENSE`, source and commit in `sigv4/testdata/NOTICE`). All 38
pass at the canonical-request, string-to-sign and signature levels. Not vendored: the SigV4a suite
(other algorithm), the `query-*` presigned variants (out of scope), S3-specific cases (none in v4).
The rest of the repository is under the licence in `LICENSE`.

## Tests

- both packages: coverage above 90 % (99 %), gated in CI by `internal/covercheck`;
- `FuzzDecode` (never panics, respects the limits, everything decoded re-encodes to the same bytes)
  and `FuzzSign` (never panics, deterministic canonical request, `Sign` repeatable); seeds committed
  under `*/testdata/fuzz/` (regenerate with `go run ./internal/genseeds`);
- CI: gofmt, vet, `go test -race` on amd64 and arm64, tests on `GOARCH=386`, cross-build and vet
  for `386` and `s390x` (32-bit and big-endian), `govulncheck`, 30 s of fuzzing per target.

## Performance

Benchmarks against `aws-sdk-go-v2` live in a separate module, `_bench/`, so the library has no
dependency (`cd _bench && go test -bench . -benchmem -cpu 1 -count 10`). `TestSameSignature` and
`TestSameWire` check that both sides do the same work. Measured only when the 1-minute load average
is at most 4.

**Measured 2026-11-03** on an Apple M4 Max, one core (`GOMAXPROCS=1`), with
go-fleettools `abbench`. Ours and the SDK run **alternately**, round by round,
from one test binary (`--base-arg`/`--head-arg` pick the sub-benchmark). Every
round waits for a 1-minute load ≤ 4 and is discarded as a pair if the load ends
above 4. Each series has 10 kept rounds; the third column is `benchstat`'s
difference (all p ≤ 0.002 unless stated).

| benchmark | ours | aws-sdk-go-v2 | |
|---|---|---|---|
| decode 1000 messages of 120 B | 287.8 µs, 6.0 k allocs | 811.6 µs, 40.0 k allocs | 2.8× faster |
| decode 1000 messages of 8 KiB | 1.265 ms, 6.0 k allocs | 2.881 ms, 44.0 k allocs | 2.3× faster |
| decode 1000 messages of 256 KiB | 42.87 ms, 9.0 k allocs | 47.05 ms, 49.0 k allocs | 1.10× faster |
| sign a Bedrock request | 2.940 µs, 48 allocs | 3.001 µs, 51 allocs | 2.0 % faster |

**Signing took two fixes to stop being slower.**
1. The first run (2026-11-01, indicative: load ended at 4.4–6.8) had signing **22 % slower**
   than the SDK. The SDK derives the signing key once per day and region/service; ours derived
   it on every request, four HMACs over eight SHA-256 blocks. v0.1.1 added the cache in
   `sigv4/keycache.go`.
2. The first clean run of that cache (2026-11-03) still had signing **1.7 % slower**
   (2.916 µs against 2.865 µs, p = 0.029). The cache key was a SHA-256 of the secret, one
   block per request.
3. The key is now a `hash/maphash` hash with a seed drawn once per process, plus the day as an
   integer instead of a formatted string. It is still stricter than the SDK's cache: two
   credentials sharing an access key ID never share an entry (only a 2⁻⁶⁴ hash collision
   could make them), the cache is bounded to 256 entries, and it holds no secret.

Encoding (one message, 3.7× faster, 1 allocation against 19) was only measured in the
indicative run of 2026-11-01.

What is designed in: no allocation in the HMAC chain
(`hmacSHA256` on the stack for the keys SigV4 uses; checked against `crypto/hmac`), one body
allocation per message, header names and short string values interned per decoder, CRC-32 through
`hash/crc32` (hardware accelerated on amd64 and arm64).

## Security notes

- **Secrets**: `Credentials` redacts the secret key and session token in `String`, `GoString` and
  `Format` (`%v %+v %#v %s %q %x ...`), also inside a `Signer` or any struct. No error contains a
  secret. A planted-secret test checks errors, prints, logs and the signed request (the session token
  appears only in `X-Amz-Security-Token`, the secret key nowhere).
- **Canonicalisation**: header names must be HTTP tokens and values are folded, so a value cannot
  forge another canonical header line; the access key, region and service cannot carry `/ , =` or
  control characters into `Credential=`.
- **Untrusted input** (event stream): all length arithmetic is in `uint64`, limits are clamped to
  what a 32-bit `int` holds, the prelude CRC is checked before the body is read, fuzzed.
- No unsafe, no cgo, no network, no files.

## Licence

See `LICENSE`. The vendored vectors are Apache-2.0 (see above).
