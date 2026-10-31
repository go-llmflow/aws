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

**Not measured, load 19-47 on 2026-10-31** (the benchmarks compile and run once). Numbers will be
added here when the machine is idle. What is designed in: no allocation in the HMAC chain
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
