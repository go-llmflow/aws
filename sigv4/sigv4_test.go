package sigv4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	plantedSecret = "S3CR3T-PLANTED-xyzzy-0123456789"
	plantedToken  = "TOKEN-PLANTED-qwerty-9876543210"
)

var t0 = time.Date(2026, 10, 31, 12, 34, 56, 789, time.UTC)

func testSigner() Signer {
	return Signer{
		Credentials: Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: plantedSecret, SessionToken: plantedToken},
		Region:      "eu-west-3", Service: "bedrock",
	}
}

func mustReq(t testing.TB, method, rawurl string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, rawurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// --- secrets never leak -----------------------------------------------------

func TestSecretNeverAppears(t *testing.T) {
	s := testSigner()
	creds := s.Credentials
	type wrapper struct {
		C  Credentials
		P  *Credentials
		S  Signer
		M  map[string]Credentials
		Sl []Credentials
	}
	w := wrapper{creds, &creds, s, map[string]Credentials{"k": creds}, []Credentials{creds}}
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d", "%T %v", "%10.3v", "%-20s"} {
		for _, arg := range []any{creds, &creds, s, &s, w, &w} {
			if strings.Contains(verb, "%T") {
				out = append(out, fmt.Sprintf(verb, arg, arg))
				continue
			}
			out = append(out, fmt.Sprintf(verb, arg))
		}
	}
	out = append(out, creds.String(), creds.GoString(), fmt.Sprint(creds), fmt.Sprintln(s), fmt.Sprint(w))
	var logbuf bytes.Buffer
	lg := log.New(&logbuf, "", 0)
	lg.Printf("%v %+v %#v", s, creds, w)
	out = append(out, logbuf.String())
	for _, o := range out {
		if strings.Contains(o, plantedSecret) || strings.Contains(o, plantedToken) {
			t.Fatalf("secret in rendering %q", o)
		}
	}
	if got := creds.String(); !strings.Contains(got, "AKIDEXAMPLE") || !strings.Contains(got, redacted) {
		t.Fatalf("rendering %q", got)
	}
	if got := (Credentials{}).String(); strings.Contains(got, redacted) {
		t.Fatalf("empty secret reported as present: %q", got)
	}
	if got := fmt.Sprintf("%#v", creds); !strings.HasPrefix(got, "sigv4.Credentials{") {
		t.Fatalf("%q", got)
	}
}

func TestSecretNeverInErrorsOrRequest(t *testing.T) {
	s := testSigner()
	bad := []*http.Request{
		nil,
		{Method: "GET"}, // nil URL
		{Method: "GET", URL: &url.URL{Path: "/"}},                                    // no host
		{Method: "GE T", URL: &url.URL{Host: "h", Path: "/"}},                        // bad method
		{Method: "GET", URL: &url.URL{Host: "h", RawQuery: "a=%zz"}},                 // bad escape
		{Method: "GET", URL: &url.URL{Host: "h", RawQuery: "a=%"}},                   // truncated escape
		{Method: "GET", URL: &url.URL{Host: "h", RawQuery: "a=%4"}},                  // truncated escape
		{Method: "GET", URL: &url.URL{Host: "h", RawQuery: "%zz=1"}},                 // bad escape in name
		{Method: "GET", URL: &url.URL{Host: "h"}, Header: http.Header{"A:b": {"v"}}}, // bad header name
		{Method: "GET", URL: &url.URL{Host: "h"}, Header: http.Header{"": {"v"}}},
	}
	for i, r := range bad {
		err := s.Sign(r, []byte("body"), t0)
		if err == nil {
			t.Fatalf("case %d: accepted", i)
		}
		if !errors.Is(err, ErrRequest) {
			t.Fatalf("case %d: %v", i, err)
		}
		if strings.Contains(err.Error(), plantedSecret) || strings.Contains(err.Error(), plantedToken) {
			t.Fatalf("case %d: secret in error %q", i, err)
		}
	}
	for _, c := range []Signer{
		{}, {Credentials: Credentials{AccessKeyID: "A/B", SecretAccessKey: plantedSecret}, Region: "r", Service: "s"},
		{Credentials: Credentials{AccessKeyID: "A", SecretAccessKey: plantedSecret}, Region: "r,x", Service: "s"},
		{Credentials: Credentials{AccessKeyID: "A", SecretAccessKey: plantedSecret}, Region: "r", Service: "s s"},
		{Credentials: Credentials{AccessKeyID: "A", SecretAccessKey: plantedSecret}, Region: "r", Service: "é"},
		{Credentials: Credentials{AccessKeyID: "A", SecretAccessKey: plantedSecret}, Region: "r"},
		{Credentials: Credentials{AccessKeyID: "A", SecretAccessKey: plantedSecret}, Service: "s"},
		{Credentials: Credentials{SecretAccessKey: plantedSecret}, Region: "r", Service: "s"},
		{Credentials: Credentials{AccessKeyID: "A"}, Region: "r", Service: "s"},
	} {
		err := c.Sign(mustReq(t, "GET", "https://h/"), nil, t0)
		if !errors.Is(err, ErrCredentials) || strings.Contains(err.Error(), plantedSecret) {
			t.Fatalf("%v: %v", c, err)
		}
	}

	req := mustReq(t, "POST", "https://bedrock-runtime.eu-west-3.amazonaws.com/model/x/invoke?a=b")
	req.Header.Set("Content-Type", "application/json")
	if err := s.Sign(req, []byte(`{"a":1}`), t0); err != nil {
		t.Fatal(err)
	}
	dump, err := httputil.DumpRequestOut(req, false)
	if err != nil {
		t.Fatal(err)
	}
	all := string(dump) + fmt.Sprintf("%+v %#v", req, req.Header) + req.URL.String()
	if strings.Contains(all, plantedSecret) {
		t.Fatal("secret key in the signed request")
	}
	// the session token travels in its own header, and nowhere else
	if n := strings.Count(string(dump), plantedToken); n != 1 || req.Header.Get(HeaderSecurityToken) != plantedToken {
		t.Fatalf("token occurrences in request: %d", n)
	}
	if strings.Contains(req.Header.Get("Authorization"), plantedToken) {
		t.Fatal("token in Authorization")
	}
}

// --- signing -----------------------------------------------------------------

func TestSignSetsHeaders(t *testing.T) {
	s := testSigner()
	req := mustReq(t, "POST", "https://bedrock-runtime.eu-west-3.amazonaws.com/model/m/converse-stream")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "x")
	req.Header.Set("Connection", "close")
	req.Header.Set("X-Amzn-Trace-Id", "Root=1")
	req.Header.Set("Transfer-Encoding", "chunked")
	if err := s.Sign(req, []byte("{}"), t0); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Amz-Date") != "20261031T123456Z" || req.Header.Get("X-Amz-Security-Token") != plantedToken {
		t.Fatal(req.Header)
	}
	auth := req.Header.Get("Authorization")
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261031/eu-west-3/bedrock/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature="
	if !strings.HasPrefix(auth, want) || len(auth) != len(want)+64 {
		t.Fatalf("Authorization %q", auth)
	}
	// signing twice gives the same result
	if err := s.Sign(req, []byte("{}"), t0); err != nil || req.Header.Get("Authorization") != auth {
		t.Fatal("Sign is not idempotent", err)
	}
	// no token: no header, not signed
	s.SessionToken = ""
	r2 := mustReq(t, "GET", "https://example.amazonaws.com/")
	if err := s.Sign(r2, nil, t0); err != nil {
		t.Fatal(err)
	}
	if _, ok := r2.Header["X-Amz-Security-Token"]; ok || strings.Contains(r2.Header.Get("Authorization"), "x-amz-security-token") {
		t.Fatal("token header without token")
	}
	// the clock is taken in UTC whatever the location of now
	loc := time.FixedZone("x", 5*3600)
	r3 := mustReq(t, "GET", "https://example.amazonaws.com/")
	if err := s.Sign(r3, nil, t0.In(loc)); err != nil || r3.Header.Get("X-Amz-Date") != "20261031T123456Z" {
		t.Fatal(err)
	}
}

func TestSignRestoresOnError(t *testing.T) {
	s := testSigner()
	req := &http.Request{Method: "GET", URL: &url.URL{Host: "h", RawQuery: "a=%zz"},
		Header: http.Header{"X-Amz-Date": {"old"}, "Authorization": {"old-auth"}}}
	if err := s.Sign(req, nil, t0); err == nil {
		t.Fatal("accepted")
	}
	if req.Header.Get("X-Amz-Date") != "old" || req.Header.Get("Authorization") != "old-auth" || req.Header.Get("X-Amz-Security-Token") != "" {
		t.Fatalf("not restored: %v", req.Header)
	}
}

func TestSignNilHeader(t *testing.T) {
	r := &http.Request{Method: "GET", URL: &url.URL{Scheme: "https", Host: "h", Path: "/"}}
	if err := testSigner().Sign(r, nil, t0); err != nil || r.Header.Get("Authorization") == "" {
		t.Fatal(err)
	}
	// empty method means GET
	c, _, err := testSigner().CanonicalRequest(r, nil)
	if err != nil || !strings.HasPrefix(c, "GET\n/\n") {
		t.Fatalf("%q %v", c, err)
	}
}

func TestPayloadHashHeaderWins(t *testing.T) {
	s := testSigner()
	r := mustReq(t, "POST", "https://h/")
	r.Header.Set(HeaderContentSHA256, "UNSIGNED-PAYLOAD")
	c, signed, err := s.CanonicalRequest(r, []byte("ignored"))
	if err != nil || !strings.HasSuffix(c, "\nUNSIGNED-PAYLOAD") || !strings.Contains(signed, "x-amz-content-sha256") {
		t.Fatalf("%q %v", c, err)
	}
	r.Header.Del(HeaderContentSHA256)
	sum := sha256.Sum256([]byte("body"))
	c, _, _ = s.CanonicalRequest(r, []byte("body"))
	if !strings.HasSuffix(c, "\n"+hex.EncodeToString(sum[:])) {
		t.Fatal(c)
	}
}

// --- the Go-side path semantics (wire form, then encode once more) -----------

func TestCanonicalURIFromWireForm(t *testing.T) {
	for _, c := range []struct {
		rawurl, service string
		disable         bool
		want            string
	}{
		{"https://h", "svc", false, "/"},
		{"https://h/", "svc", false, "/"},
		// URL.Path "/a b" is "/a%20b" on the wire; the canonical URI encodes it again.
		{"https://h/a%20b", "svc", false, "/a%2520b"},
		{"https://h/model/anthropic.claude-3:0/invoke", "bedrock", false, "/model/anthropic.claude-3%3A0/invoke"},
		{"https://h/model/arn%3Aaws%3Abedrock/invoke", "bedrock", false, "/model/arn%253Aaws%253Abedrock/invoke"},
		{"https://h/a/../b/./c//d/", "svc", false, "/b/c/d/"},
		{"https://h/a/../b/./c//d/", "svc", true, "/a/../b/./c//d/"},
		{"https://h/a/%2e%2e/b", "svc", false, "/a/%252e%252e/b"}, // encoded dots are not dot segments
		// S3: the escaped path as it is, no normalisation
		{"https://h/a%20b//c/../d", "s3", false, "/a%20b//c/../d"},
		{"https://h/a%20b", "s3-outposts", false, "/a%20b"},
		{"https://h/ሴ", "svc", false, "/%25E1%2588%25B4"}, // Go escapes to %E1%88%B4, encoded again
	} {
		s := testSigner()
		s.Service, s.DisableNormalize = c.service, c.disable
		req := mustReq(t, "GET", c.rawurl)
		canon, _, err := s.CanonicalRequest(req, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Split(canon, "\n")[1]; got != c.want {
			t.Errorf("%s (%s): got %q want %q", c.rawurl, c.service, got, c.want)
		}
	}
}

func TestOpaqueURL(t *testing.T) {
	s := testSigner()
	for _, c := range []struct{ opaque, want string }{
		{"//host/a b", "/a%20b"}, {"//host", "/"}, {"/x y", "/x%20y"},
	} {
		req := &http.Request{Method: "GET", URL: &url.URL{Scheme: "https", Host: "host", Opaque: c.opaque}}
		canon, _, err := s.CanonicalRequest(req, nil)
		if err != nil || strings.Split(canon, "\n")[1] != c.want {
			t.Errorf("%q: %q %v", c.opaque, canon, err)
		}
	}
}

func TestNormalizePath(t *testing.T) {
	for in, want := range map[string]string{
		"": "/", "/": "/", "//": "/", "/a": "/a", "/a/": "/a/", "/a//b": "/a/b", "/a/.": "/a/", "/a/..": "/",
		"/a/../..": "/", "/..": "/", "/../a": "/a", "/./a/./b/": "/a/b/", "/a/b/../c": "/a/c", "///": "/",
	} {
		if got := normalizePath(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestURIEncode(t *testing.T) {
	if got := uriEncode("-._~AZaz09/ !*'()+,:;=@[]\xff", false); got != "-._~AZaz09%2F%20%21%2A%27%28%29%2B%2C%3A%3B%3D%40%5B%5D%FF" {
		t.Fatal(got)
	}
	if got := uriEncode("a/b c", true); got != "a/b%20c" {
		t.Fatal(got)
	}
}

func TestCanonicalQuery(t *testing.T) {
	for in, want := range map[string]string{
		"":                     "",
		"b=2&a=1":              "a=1&b=2",
		"a=2&a=1&a=":           "a=&a=1&a=2",
		"k":                    "k=",
		"&&a=1&":               "a=1",
		"a=b=c":                "a=b%3Dc",
		"a+b=c+d":              "a%20b=c%20d",
		"a%2Bb=%7e":            "a%2Bb=~",
		"a%2fb=1&a%2Fb=0":      "a%2Fb=0&a%2Fb=1",
		"z=1&Z=2&%C3%A9=3&e=4": "%C3%A9=3&Z=2&e=4&z=1",
		"x=%E1%88%B4&x=ሴ":      "x=%E1%88%B4&x=%E1%88%B4",
	} {
		got, err := canonicalQuery(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q (%v) want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"a=%", "a=%1", "a=%g0", "%=1", "a=%0"} {
		if _, err := canonicalQuery(bad); !errors.Is(err, ErrRequest) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestCanonicalHeaders(t *testing.T) {
	h := http.Header{
		"X-Amz-Target":  {"  a   b  ", "c"},
		"x-amz-target":  {"d"}, // a non-canonical key merges, in key order
		"Content-Type":  {"text/plain"},
		"Authorization": {"old"},
		"User-Agent":    {"ua"},
		"Host":          {"ignored.example"},
		"Te":            {"trailers"},
		"X-Tab":         {"a\t\tb\nc"},
		"X-Empty":       {""},
		"X-None":        nil,
	}
	lines, signed, err := canonicalHeaders(h, "real.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	wantLines := "content-type:text/plain\nhost:real.example:8443\nx-amz-target:a b,c,d\nx-empty:\nx-none:\nx-tab:a b c\n"
	if lines != wantLines || signed != "content-type;host;x-amz-target;x-empty;x-none;x-tab" {
		t.Fatalf("%q\n%q", lines, signed)
	}
	for _, name := range []string{"A B", "A:B", "A\nB", "é", ""} {
		if _, _, err := canonicalHeaders(http.Header{name: {"v"}}, "h"); !errors.Is(err, ErrRequest) {
			t.Errorf("name %q accepted", name)
		}
	}
	// a value cannot forge another header line
	lines, _, _ = canonicalHeaders(http.Header{"X-A": {"1\nx-amz-forged:yes"}}, "h")
	if strings.Contains(lines, "\nx-amz-forged:") {
		t.Fatalf("header injection: %q", lines)
	}
}

func TestCollapse(t *testing.T) {
	for in, want := range map[string]string{
		"": "", " ": "", "a": "a", " a ": "a", "a  b": "a b", "a\tb": "a b", "\n a \r\n b\v": "a b", "a b": "a b",
		`"a   b   c"`: `"a b c"`, "x y": "x y",
	} {
		if got := collapse(in); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

func TestIsToken(t *testing.T) {
	for _, s := range []string{"GET", "X-Amz-Date", "a!#$%&'*+-.^_`|~9"} {
		if !isToken(s) {
			t.Errorf("%q", s)
		}
	}
	for _, s := range []string{"", "a b", "a:b", "a(", "a\x7f", "é"} {
		if isToken(s) {
			t.Errorf("%q", s)
		}
	}
}

// --- HMAC --------------------------------------------------------------------

func TestHMACMatchesStdlib(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, kl := range []int{0, 1, 32, 44, 63, 64, 65, 100, 200} {
		for _, ml := range []int{0, 1, 8, 20, 127, 128, 129, 300} {
			key, msg := make([]byte, kl), make([]byte, ml)
			rng.Read(key)
			rng.Read(msg)
			m := hmac.New(sha256.New, key)
			m.Write(msg)
			var got [32]byte
			hmacSHA256(&got, key, msg)
			if !bytes.Equal(got[:], m.Sum(nil)) {
				t.Fatalf("key %d msg %d", kl, ml)
			}
		}
	}
	// dst may alias key
	key := bytes.Repeat([]byte{7}, 32)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("x"))
	want := m.Sum(nil)
	var k [32]byte
	copy(k[:], key)
	hmacSHA256(&k, k[:], []byte("x"))
	if !bytes.Equal(k[:], want) {
		t.Fatal("aliasing")
	}
}

// A secret longer than one HMAC block takes the crypto/hmac path.
func TestLongSecret(t *testing.T) {
	s := testSigner()
	s.SecretAccessKey = strings.Repeat("k", 200)
	r := mustReq(t, "GET", "https://h/")
	if err := s.Sign(r, nil, t0); err != nil {
		t.Fatal(err)
	}
	var want [32]byte
	m := hmac.New(sha256.New, []byte("AWS4"+s.SecretAccessKey))
	m.Write([]byte("20261031"))
	m2 := hmac.New(sha256.New, m.Sum(nil))
	m2.Write([]byte(s.Region))
	m3 := hmac.New(sha256.New, m2.Sum(nil))
	m3.Write([]byte(s.Service))
	m4 := hmac.New(sha256.New, m3.Sum(nil))
	m4.Write([]byte("aws4_request"))
	copy(want[:], m4.Sum(nil))
	var got [32]byte
	s.signingKey(&got, t0)
	if got != want {
		t.Fatal("signing key differs from the stdlib chain")
	}
}

// --- fuzz --------------------------------------------------------------------

// FuzzSign: Sign and CanonicalRequest never panic whatever the request, the
// canonical request is deterministic, and a successful Sign is repeatable.
func FuzzSign(f *testing.F) {
	f.Add("GET", "https://example.amazonaws.com/", "My-Header", "value", []byte(nil), int64(1440938160), "service")
	f.Add("POST", "https://h/a b/../c//d?b=2&a=%41&a=+", "Content-Type", "  a   b ", []byte("body"), int64(0), "s3")
	f.Add("PUT", "https://h:8443/%E1%88%B4?%zz", "X-Amz-Target", "a\nb", []byte{0xff}, int64(-1), "bedrock")
	f.Fuzz(func(t *testing.T, method, rawurl, hname, hvalue string, body []byte, unix int64, service string) {
		req, err := http.NewRequest(method, rawurl, nil)
		if err != nil {
			t.Skip()
		}
		if hname != "" {
			req.Header[hname] = append(req.Header[hname], hvalue)
		}
		s := Signer{
			Credentials: Credentials{AccessKeyID: "AKID", SecretAccessKey: plantedSecret, SessionToken: plantedToken},
			Region:      "us-east-1", Service: service,
		}
		now := time.Unix(unix%1e11, 0).UTC()
		c1, sh1, err1 := s.CanonicalRequest(req, body)
		c2, sh2, err2 := s.CanonicalRequest(req, body)
		if c1 != c2 || sh1 != sh2 || (err1 == nil) != (err2 == nil) {
			t.Fatal("CanonicalRequest is not deterministic")
		}
		errSign := s.Sign(req, body, now)
		if errSign != nil {
			if strings.Contains(errSign.Error(), plantedSecret) || strings.Contains(errSign.Error(), plantedToken) {
				t.Fatal("secret in error")
			}
			return
		}
		auth := req.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKID/") || strings.Contains(auth, plantedSecret) || strings.Contains(auth, plantedToken) {
			t.Fatalf("Authorization %q", auth)
		}
		if err := s.Sign(req, body, now); err != nil || req.Header.Get("Authorization") != auth {
			t.Fatal("Sign is not repeatable")
		}
	})
}
