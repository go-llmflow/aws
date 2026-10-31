// Package bench compares go-llmflow/aws with the AWS SDK for Go v2 on the same
// inputs. It is a separate module so that the library keeps no dependency.
//
//	cd _bench && go test -bench . -benchmem -cpu 1 -count 10
//
// Measure only on an idle machine (1-minute load average <= 4), interleaving
// the two sides (the benchmarks are named so that benchstat can pair them).
package bench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkes "github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/go-llmflow/aws/eventstream"
	"github.com/go-llmflow/aws/sigv4"
)

// --- event stream ------------------------------------------------------------

// stream returns n messages shaped like a Bedrock ConverseStream event:
// three string headers and a small JSON payload (or a large one).
func stream(tb testing.TB, n, payload int) []byte {
	var buf bytes.Buffer
	p := bytes.Repeat([]byte("x"), payload)
	for i := 0; i < n; i++ {
		err := eventstream.Encode(&buf, eventstream.Message{
			Headers: []eventstream.Header{
				{Name: ":event-type", Value: eventstream.String("contentBlockDelta")},
				{Name: ":content-type", Value: eventstream.String("application/json")},
				{Name: ":message-type", Value: eventstream.String("event")},
			},
			Payload: p,
		})
		if err != nil {
			tb.Fatal(err)
		}
	}
	return buf.Bytes()
}

func BenchmarkDecode(b *testing.B) {
	const n = 1000
	for _, payload := range []int{120, 8 << 10, 256 << 10} {
		wire := stream(b, n, payload)
		name := strconv.Itoa(payload) + "B"
		b.Run("ours/"+name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(wire)))
			for i := 0; i < b.N; i++ {
				d := eventstream.NewDecoder(bytes.NewReader(wire), eventstream.Limits{})
				for {
					if _, err := d.Next(); err == io.EOF {
						break
					} else if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
		b.Run("sdk/"+name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(wire)))
			for i := 0; i < b.N; i++ {
				d := sdkes.NewDecoder()
				r := bytes.NewReader(wire)
				for {
					if _, err := d.Decode(r, nil); err == io.EOF {
						break
					} else if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func BenchmarkEncode(b *testing.B) {
	m := eventstream.Message{
		Headers: []eventstream.Header{
			{Name: ":event-type", Value: eventstream.String("contentBlockDelta")},
			{Name: ":content-type", Value: eventstream.String("application/json")},
			{Name: ":message-type", Value: eventstream.String("event")},
		},
		Payload: bytes.Repeat([]byte("x"), 120),
	}
	sm := sdkes.Message{
		Headers: sdkes.Headers{
			{Name: ":event-type", Value: sdkes.StringValue("contentBlockDelta")},
			{Name: ":content-type", Value: sdkes.StringValue("application/json")},
			{Name: ":message-type", Value: sdkes.StringValue("event")},
		},
		Payload: m.Payload,
	}
	b.Run("ours", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := eventstream.Encode(io.Discard, m); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("sdk", func(b *testing.B) {
		b.ReportAllocs()
		e := sdkes.NewEncoder()
		for i := 0; i < b.N; i++ {
			if err := e.Encode(io.Discard, sm); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// --- SigV4 -------------------------------------------------------------------

var (
	signTime = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	body     = []byte(`{"messages":[{"role":"user","content":[{"text":"hello"}]}],"inferenceConfig":{"maxTokens":256}}`)
	target   = "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse-stream"
)

func newReq(b *testing.B) *http.Request {
	r, err := http.NewRequest("POST", target, nil)
	if err != nil {
		b.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}

func BenchmarkSign(b *testing.B) {
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	b.Run("ours", func(b *testing.B) {
		s := sigv4.Signer{
			Credentials: sigv4.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", SessionToken: "tok"},
			Region:      "us-east-1", Service: "bedrock",
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := s.Sign(newReq(b), body, signTime); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("sdk", func(b *testing.B) {
		s := v4.NewSigner()
		creds := aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", SessionToken: "tok"}
		ctx := context.Background()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := s.SignHTTP(ctx, creds, newReq(b), hash, "bedrock", "us-east-1", signTime); err != nil {
				b.Fatal(err)
			}
		}
	})
	// the baseline both include: building the request
	b.Run("request-only", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = newReq(b)
		}
	})
}

// TestSameSignature guards the comparison (both implementations must agree,
// otherwise the numbers compare different work), and it is the independent
// witness for the paths go-llmflow/gateway signs for Bedrock: a model ID in
// the path is percent-encoded once by the caller (":" as %3A, "/" as %2F) and
// SigV4 encodes it again for a non-S3 service. A fake server that verifies
// with this same library cannot see a double-encoding mistake; the SDK can.
// CI runs it (the "sdk-witness" job).
func TestSameSignature(t *testing.T) {
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	const host = "https://bedrock-runtime.eu-west-3.amazonaws.com"
	targets := map[string]string{
		"converse-stream, base model":   target,
		"invoke, base model":            host + "/model/anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke",
		"stream, EU inference profile":  host + "/model/eu.anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke-with-response-stream",
		"invoke, inference-profile ARN": host + "/model/arn%3Aaws%3Abedrock%3Aeu-west-3%3A123456789012%3Ainference-profile%2Feu.anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke",
	}
	for name, u := range targets {
		for _, tok := range []string{"", "tok"} {
			mk := func() *http.Request {
				r, err := http.NewRequest("POST", u, nil)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Accept", "application/vnd.amazon.eventstream")
				return r
			}
			ours := mk()
			s := sigv4.Signer{
				Credentials: sigv4.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", SessionToken: tok},
				Region:      "eu-west-3", Service: "bedrock",
			}
			if err := s.Sign(ours, body, signTime); err != nil {
				t.Fatal(err)
			}
			theirs := mk()
			creds := aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", SessionToken: tok}
			if err := v4.NewSigner().SignHTTP(context.Background(), creds, theirs, hash, "bedrock", "eu-west-3", signTime); err != nil {
				t.Fatal(err)
			}
			if a, b := ours.Header.Get("Authorization"), theirs.Header.Get("Authorization"); a != b {
				t.Errorf("%s (token %q): signatures differ:\n ours %s\n  sdk %s", name, tok, a, b)
			}
		}
	}
}

// TestSameWire guards the event-stream comparison the same way.
func TestSameWire(t *testing.T) {
	wire := stream(t, 3, 50)
	d := sdkes.NewDecoder()
	r := bytes.NewReader(wire)
	for i := 0; i < 3; i++ {
		m, err := d.Decode(r, nil)
		if err != nil || len(m.Payload) != 50 || len(m.Headers) != 3 {
			t.Fatalf("sdk cannot read our wire: %v", err)
		}
	}
}
