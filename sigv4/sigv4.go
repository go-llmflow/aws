// Package sigv4 signs HTTP requests with AWS Signature Version 4, using only
// the standard library.
//
// It follows "Create a signed AWS API request" and the pages it links:
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
//
//	CanonicalRequest = Method \n CanonicalURI \n CanonicalQueryString \n
//	                   CanonicalHeaders \n SignedHeaders \n HashedPayload
//	StringToSign     = "AWS4-HMAC-SHA256" \n <YYYYMMDDTHHMMSSZ> \n
//	                   <YYYYMMDD/region/service/aws4_request> \n hex(SHA256(CanonicalRequest))
//	SigningKey       = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
//	Authorization    = AWS4-HMAC-SHA256 Credential=AKID/scope, SignedHeaders=a;b, Signature=hex(HMAC(SigningKey, StringToSign))
//
// The implementation is checked against the aws-c-auth SigV4 test suite
// (https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4),
// vendored in testdata/ with its Apache-2.0 licence, at the canonical-request,
// string-to-sign and signature levels.
//
// Choices a caller should know about:
//
//   - Every header present on the request is signed except the ones in
//     [UnsignedHeaders] (hop-by-hop headers and headers proxies rewrite);
//     "host" (req.Host, else req.URL.Host, exactly what net/http sends) is
//     always signed, as are X-Amz-Date and X-Amz-Security-Token.
//   - The payload hash is the value of an X-Amz-Content-Sha256 header if the
//     request carries one (for example "UNSIGNED-PAYLOAD"), else hex(SHA-256(body)).
//   - The canonical URI is built from req.URL.EscapedPath(), the form that is
//     on the wire. Services other than S3 then encode it once more ("double
//     encoding") and normalise it (dot segments and repeated slashes removed).
//     For service "s3" (and "s3-outposts") the escaped path is used as is.
//   - '+' in a query string is a space, as net/url and AWS both read it.
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Algorithm is the SigV4 signing algorithm identifier.
const Algorithm = "AWS4-HMAC-SHA256"

const (
	amzDateFormat = "20060102T150405Z"
	dateFormat    = "20060102"

	// HeaderDate and HeaderSecurityToken are set by Sign.
	HeaderDate          = "X-Amz-Date"
	HeaderSecurityToken = "X-Amz-Security-Token"
	// HeaderContentSHA256, if present, supplies the hashed payload.
	HeaderContentSHA256 = "X-Amz-Content-Sha256"
)

// Errors returned by this package. None carries a secret.
var (
	ErrCredentials = errors.New("sigv4: missing or malformed credentials, region or service")
	ErrRequest     = errors.New("sigv4: request cannot be canonicalised")
)

// UnsignedHeaders lists (lower-case) the headers that are never signed:
// hop-by-hop headers (RFC 9110 section 7.6.1), headers that proxies add or
// rewrite, and Authorization itself.
var UnsignedHeaders = map[string]bool{
	"authorization":       true,
	"connection":          true,
	"expect":              true,
	"keep-alive":          true,
	"proxy-authorization": true,
	"proxy-connection":    true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"user-agent":          true,
	"x-amzn-trace-id":     true,
}

// Signer signs requests for one region and service. The embedded Credentials
// redact themselves when printed; so does a Signer.
type Signer struct {
	Credentials
	Region  string // e.g. "us-east-1"
	Service string // signing name, e.g. "bedrock" or "s3"

	// DisableNormalize keeps the path as is (no dot-segment or slash
	// merging). Always on for S3.
	DisableNormalize bool
}

func (s Signer) isS3() bool { return s.Service == "s3" || s.Service == "s3-outposts" }

func (s Signer) check() error {
	if s.AccessKeyID == "" || s.SecretAccessKey == "" || s.Region == "" || s.Service == "" {
		return ErrCredentials
	}
	// These end up in the Credential= field: no separator may be smuggled in.
	for _, f := range []string{s.AccessKeyID, s.Region, s.Service} {
		for i := 0; i < len(f); i++ {
			if c := f[i]; c <= ' ' || c == '/' || c == ',' || c == '=' || c >= 0x7f {
				return ErrCredentials
			}
		}
	}
	return nil
}

// Scope returns the credential scope "YYYYMMDD/region/service/aws4_request".
func (s Signer) Scope(t time.Time) string {
	return t.UTC().Format(dateFormat) + "/" + s.Region + "/" + s.Service + "/aws4_request"
}

// Sign signs req in place with the given body (nil or empty for none) at
// time now. It sets X-Amz-Date, X-Amz-Security-Token (if SessionToken is set)
// and Authorization. The body is only hashed, never read from req.Body. Sign
// may be called again on the same request; it replaces what it set before.
// On error the request is left as it was.
func (s Signer) Sign(req *http.Request, body []byte, now time.Time) error {
	if err := s.check(); err != nil {
		return err
	}
	if req == nil || req.URL == nil {
		return fmt.Errorf("%w: nil request or URL", ErrRequest)
	}
	if req.Header == nil {
		req.Header = http.Header{}
	}
	h := req.Header
	oldDate, hadDate := h[HeaderDate]
	oldTok, hadTok := h[HeaderSecurityToken]
	oldAuth, hadAuth := h["Authorization"]
	restore := func() {
		put := func(k string, v []string, had bool) {
			if had {
				h[k] = v
			} else {
				delete(h, k)
			}
		}
		put(HeaderDate, oldDate, hadDate)
		put(HeaderSecurityToken, oldTok, hadTok)
		put("Authorization", oldAuth, hadAuth)
	}

	now = now.UTC()
	amzDate := now.Format(amzDateFormat)
	h.Set(HeaderDate, amzDate)
	if s.SessionToken != "" {
		h.Set(HeaderSecurityToken, s.SessionToken)
	}
	h.Del("Authorization")

	canonical, signed, err := s.CanonicalRequest(req, body)
	if err != nil {
		restore()
		return err
	}
	scope := s.Scope(now)
	sts := StringToSign(now, scope, canonical)

	var key, sig [32]byte
	s.signingKey(&key, now)
	hmacSHA256(&sig, key[:], []byte(sts))

	var b strings.Builder
	b.Grow(len(Algorithm) + len(s.AccessKeyID) + len(scope) + len(signed) + 64 + 40)
	b.WriteString(Algorithm)
	b.WriteString(" Credential=")
	b.WriteString(s.AccessKeyID)
	b.WriteByte('/')
	b.WriteString(scope)
	b.WriteString(", SignedHeaders=")
	b.WriteString(signed)
	b.WriteString(", Signature=")
	var hx [64]byte
	hex.Encode(hx[:], sig[:])
	b.Write(hx[:])
	h.Set("Authorization", b.String())
	return nil
}

// StringToSign builds the string to sign from the request time, the
// credential scope and the canonical request.
func StringToSign(t time.Time, scope, canonicalRequest string) string {
	sum := sha256.Sum256([]byte(canonicalRequest))
	var hx [64]byte
	hex.Encode(hx[:], sum[:])
	return Algorithm + "\n" + t.UTC().Format(amzDateFormat) + "\n" + scope + "\n" + string(hx[:])
}

// signingKey derives HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request").
func (s Signer) signingKey(dst *[32]byte, t time.Time) {
	var k [32]byte
	var kb [64]byte // "AWS4"+secret on the stack when it fits one HMAC block
	seed := append(kb[:0], "AWS4"...)
	seed = append(seed, s.SecretAccessKey...)
	hmacSHA256(&k, seed, []byte(t.UTC().Format(dateFormat)))
	hmacSHA256(&k, k[:], []byte(s.Region))
	hmacSHA256(&k, k[:], []byte(s.Service))
	hmacSHA256(dst, k[:], []byte("aws4_request"))
}

// hmacSHA256 computes HMAC-SHA256(key, msg) into dst. For the short keys and
// messages SigV4 uses it needs no heap allocation (RFC 2104: H((K^opad) ||
// H((K^ipad) || m)) with a key of at most one block); anything longer goes
// through crypto/hmac. dst may alias key.
func hmacSHA256(dst *[32]byte, key, msg []byte) {
	const block = 64
	if len(key) > block || len(msg) > 128 {
		m := hmac.New(sha256.New, key)
		m.Write(msg)
		m.Sum(dst[:0])
		return
	}
	var pad [block + 128]byte
	for i := 0; i < block; i++ {
		var k byte
		if i < len(key) {
			k = key[i]
		}
		pad[i] = k ^ 0x36
	}
	n := copy(pad[block:], msg)
	inner := sha256.Sum256(pad[:block+n])
	var outer [block + 32]byte
	for i := 0; i < block; i++ {
		var k byte
		if i < len(key) {
			k = key[i]
		}
		outer[i] = k ^ 0x5c
	}
	copy(outer[block:], inner[:])
	*dst = sha256.Sum256(outer[:])
}

// CanonicalRequest returns the canonical request of req (which should
// already carry X-Amz-Date and, if used, X-Amz-Security-Token, as Sign sets
// them) and the SignedHeaders list. body is hashed unless req carries an
// X-Amz-Content-Sha256 header.
func (s Signer) CanonicalRequest(req *http.Request, body []byte) (canonical, signedHeaders string, err error) {
	if req == nil || req.URL == nil {
		return "", "", fmt.Errorf("%w: nil request or URL", ErrRequest)
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	if !isToken(method) {
		return "", "", fmt.Errorf("%w: invalid method", ErrRequest)
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		return "", "", fmt.Errorf("%w: no host", ErrRequest)
	}

	path := wirePath(req)
	if !s.isS3() {
		if !s.DisableNormalize {
			path = normalizePath(path)
		}
		path = uriEncode(path, true)
	}
	if path == "" {
		path = "/"
	}
	query, err := canonicalQuery(req.URL.RawQuery)
	if err != nil {
		return "", "", err
	}
	hdrs, signedHeaders, err := canonicalHeaders(req.Header, host)
	if err != nil {
		return "", "", err
	}

	payload := req.Header.Get(HeaderContentSHA256)
	if payload == "" {
		sum := sha256.Sum256(body)
		payload = hex.EncodeToString(sum[:])
	} else {
		payload = collapse(payload)
	}

	var b strings.Builder
	b.Grow(len(method) + len(path) + len(query) + len(hdrs) + len(signedHeaders) + len(payload) + 8)
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(path)
	b.WriteByte('\n')
	b.WriteString(query)
	b.WriteByte('\n')
	b.WriteString(hdrs)
	b.WriteByte('\n')
	b.WriteString(signedHeaders)
	b.WriteByte('\n')
	b.WriteString(payload)
	return b.String(), signedHeaders, nil
}

// wirePath returns the request path as it is on the wire.
func wirePath(req *http.Request) string {
	u := req.URL
	if u.Opaque != "" {
		p := u.Opaque
		if u.Scheme != "" && strings.HasPrefix(p, "//") { // scheme://host/path form
			if i := strings.IndexByte(p[2:], '/'); i >= 0 {
				return p[2+i:]
			}
			return "/"
		}
		return p
	}
	if p := u.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

// normalizePath removes "." and ".." segments and empty segments, keeping a
// trailing slash (RFC 3986 section 5.2.4 plus slash merging).
func normalizePath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	trailing := strings.HasSuffix(p, "/")
	segs := strings.Split(p, "/")
	out := segs[:0:0]
	for i, sg := range segs {
		switch sg {
		case "", ".":
			if sg == "." && i == len(segs)-1 {
				trailing = true
			}
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if i == len(segs)-1 {
				trailing = true
			}
		default:
			out = append(out, sg)
		}
	}
	if len(out) == 0 {
		return "/"
	}
	r := "/" + strings.Join(out, "/")
	if trailing {
		r += "/"
	}
	return r
}

const upperhex = "0123456789ABCDEF"

func unreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// uriEncode is the SigV4 UriEncode: everything but A-Z a-z 0-9 - . _ ~ is
// percent-encoded with upper-case hex (space is %20); '/' is kept if keepSlash.
func uriEncode(s string, keepSlash bool) string {
	n := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; !unreserved(c) && !(keepSlash && c == '/') {
			n++
		}
	}
	if n == 0 {
		return s
	}
	b := make([]byte, 0, len(s)+2*n)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if unreserved(c) || keepSlash && c == '/' {
			b = append(b, c)
		} else {
			b = append(b, '%', upperhex[c>>4], upperhex[c&15])
		}
	}
	return string(b)
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// queryDecode percent-decodes a query component, '+' being a space.
func queryDecode(s string) (string, error) {
	if !strings.ContainsAny(s, "%+") {
		return s, nil
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '+':
			b = append(b, ' ')
		case '%':
			if i+2 >= len(s) {
				return "", fmt.Errorf("%w: bad percent-escape in query", ErrRequest)
			}
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if !ok1 || !ok2 {
				return "", fmt.Errorf("%w: bad percent-escape in query", ErrRequest)
			}
			b = append(b, hi<<4|lo)
			i += 2
		default:
			b = append(b, c)
		}
	}
	return string(b), nil
}

type kv struct{ k, v string }

// canonicalQuery encodes names and values separately and sorts by name,
// then by value, after encoding.
func canonicalQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	pairs := make([]kv, 0, strings.Count(raw, "&")+1)
	for len(raw) > 0 {
		var part string
		if i := strings.IndexByte(raw, '&'); i >= 0 {
			part, raw = raw[:i], raw[i+1:]
		} else {
			part, raw = raw, ""
		}
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		dn, err := queryDecode(name)
		if err != nil {
			return "", err
		}
		dv, err := queryDecode(val)
		if err != nil {
			return "", err
		}
		pairs = append(pairs, kv{uriEncode(dn, false), uriEncode(dv, false)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.k)
		b.WriteByte('=')
		b.WriteString(p.v)
	}
	return b.String(), nil
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	return true
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

// collapse trims v and folds every run of white space into one space.
func collapse(v string) string {
	clean := true
	for i := 0; i < len(v); i++ {
		if isSpace(v[i]) && (v[i] != ' ' || i == 0 || i == len(v)-1 || isSpace(v[i+1])) {
			clean = false
			break
		}
	}
	if clean {
		return v
	}
	b := make([]byte, 0, len(v))
	pending := false
	for i := 0; i < len(v); i++ {
		if isSpace(v[i]) {
			pending = len(b) > 0
			continue
		}
		if pending {
			b = append(b, ' ')
			pending = false
		}
		b = append(b, v[i])
	}
	return string(b)
}

type hent struct{ lower, orig string }

// canonicalHeaders returns "name:value\n" lines (lower-case names, sorted,
// values trimmed and collapsed, repeated names joined with ",") and the
// SignedHeaders list. Host always comes from host, never from the map.
func canonicalHeaders(h http.Header, host string) (lines, signed string, err error) {
	ents := make([]hent, 0, len(h)+1)
	for k := range h {
		if !isToken(k) {
			return "", "", fmt.Errorf("%w: invalid header name", ErrRequest)
		}
		l := strings.ToLower(k)
		if l == "host" || UnsignedHeaders[l] {
			continue
		}
		ents = append(ents, hent{l, k})
	}
	ents = append(ents, hent{"host", ""})
	sort.Slice(ents, func(i, j int) bool {
		if ents[i].lower != ents[j].lower {
			return ents[i].lower < ents[j].lower
		}
		return ents[i].orig < ents[j].orig
	})

	var lb, sb strings.Builder
	for i := 0; i < len(ents); {
		name := ents[i].lower
		if i > 0 {
			sb.WriteByte(';')
		}
		sb.WriteString(name)
		lb.WriteString(name)
		lb.WriteByte(':')
		first := true
		for ; i < len(ents) && ents[i].lower == name; i++ {
			vals := h[ents[i].orig]
			if name == "host" {
				vals = []string{host}
			}
			for _, v := range vals {
				if !first {
					lb.WriteByte(',')
				}
				first = false
				lb.WriteString(collapse(v))
			}
		}
		lb.WriteByte('\n')
	}
	return lb.String(), sb.String(), nil
}
