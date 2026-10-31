package sigv4

import (
	"fmt"
	"strings"
)

const redacted = "[REDACTED]"

// Credentials are long-term or temporary AWS credentials.
//
// The secret key and session token are never rendered: String, GoString and
// Format (which fmt uses for %v, %+v, %#v, %s and %q) replace them with a
// placeholder, and no error returned by this package contains them.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

func (c Credentials) render(goSyntax bool) string {
	set := func(s string) string {
		if s == "" {
			return `""`
		}
		return redacted
	}
	var b strings.Builder
	if goSyntax {
		b.WriteString("sigv4.")
	}
	fmt.Fprintf(&b, "Credentials{AccessKeyID:%q, SecretAccessKey:%s, SessionToken:%s}",
		c.AccessKeyID, set(c.SecretAccessKey), set(c.SessionToken))
	return b.String()
}

// String returns a rendering with the secrets redacted.
func (c Credentials) String() string { return c.render(false) }

// GoString returns a Go-syntax rendering with the secrets redacted.
func (c Credentials) GoString() string { return c.render(true) }

// Format implements fmt.Formatter so that no verb can reach the secrets.
func (c Credentials) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = fmt.Fprint(f, c.GoString())
		return
	}
	_, _ = fmt.Fprint(f, c.String())
}
