package sigv4

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type vectorContext struct {
	Credentials struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		Token           string `json:"token"`
	} `json:"credentials"`
	Normalize        bool   `json:"normalize"`
	Region           string `json:"region"`
	Service          string `json:"service"`
	SignBody         bool   `json:"sign_body"`
	Timestamp        string `json:"timestamp"`
	OmitSessionToken bool   `json:"omit_session_token"`
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// parseVector turns an aws-c-auth request.txt into a request. The request
// path of the suite is the raw, unescaped text; it is handed over as the
// URL's Opaque form, which Signer treats as the wire path.
func parseVector(t *testing.T, raw string) (*http.Request, []byte) {
	t.Helper()
	head, body, _ := strings.Cut(raw, "\n\n")
	lines := strings.Split(head, "\n")
	method, rest, ok1 := strings.Cut(lines[0], " ")
	target, ok2 := strings.CutSuffix(rest, " HTTP/1.1") // the target may contain spaces
	if !ok1 || !ok2 {
		t.Fatalf("request line %q", lines[0])
	}
	path, query, _ := strings.Cut(target, "?")
	req := &http.Request{Method: method, URL: &url.URL{Opaque: path, RawQuery: query}, Header: http.Header{}}
	var lastKey string
	for _, l := range lines[1:] {
		if l == "" {
			continue
		}
		if l[0] == ' ' || l[0] == '\t' { // obsolete line folding
			vs := req.Header[lastKey]
			vs[len(vs)-1] += " " + strings.TrimSpace(l)
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			t.Fatalf("header line %q", l)
		}
		if strings.EqualFold(k, "host") {
			req.Host = v
			lastKey = ""
			continue
		}
		lastKey = http.CanonicalHeaderKey(k)
		req.Header.Add(lastKey, v)
	}
	return req, []byte(body)
}

func TestAWSSigningTestSuite(t *testing.T) {
	dirs, err := filepath.Glob("testdata/v4/*")
	if err != nil || len(dirs) != 38 {
		t.Fatalf("expected 38 vendored cases, got %d (%v)", len(dirs), err)
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			var c vectorContext
			if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "context.json"))), &c); err != nil {
				t.Fatal(err)
			}
			now, err := time.Parse(time.RFC3339, c.Timestamp)
			if err != nil {
				t.Fatal(err)
			}
			req, body := parseVector(t, readFile(t, filepath.Join(dir, "request.txt")))
			if c.SignBody {
				sum := sha256.Sum256(body)
				req.Header.Set(HeaderContentSHA256, hex.EncodeToString(sum[:]))
			}
			s := Signer{
				Credentials: Credentials{AccessKeyID: c.Credentials.AccessKeyID, SecretAccessKey: c.Credentials.SecretAccessKey},
				Region:      c.Region, Service: c.Service, DisableNormalize: !c.Normalize,
			}
			if !c.OmitSessionToken {
				s.SessionToken = c.Credentials.Token
			}
			if err := s.Sign(req, body, now); err != nil {
				t.Fatal(err)
			}

			wantCanon := readFile(t, filepath.Join(dir, "header-canonical-request.txt"))
			canon, signed, err := s.CanonicalRequest(req, body)
			if err != nil {
				t.Fatal(err)
			}
			if canon != wantCanon {
				t.Fatalf("canonical request:\n got %q\nwant %q", canon, wantCanon)
			}

			wantSTS := readFile(t, filepath.Join(dir, "header-string-to-sign.txt"))
			if sts := StringToSign(now, s.Scope(now), canon); sts != wantSTS {
				t.Fatalf("string to sign:\n got %q\nwant %q", sts, wantSTS)
			}

			wantSig := strings.TrimSpace(readFile(t, filepath.Join(dir, "header-signature.txt")))
			want := "AWS4-HMAC-SHA256 Credential=" + c.Credentials.AccessKeyID + "/" + s.Scope(now) +
				", SignedHeaders=" + signed + ", Signature=" + wantSig
			if got := req.Header.Get("Authorization"); got != want {
				t.Fatalf("Authorization:\n got %q\nwant %q", got, want)
			}
		})
	}
}
