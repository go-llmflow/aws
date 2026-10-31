package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const profile = `mode: atomic
github.com/x/m/sigv4/a.go:1.1,2.2 3 1
github.com/x/m/sigv4/a.go:3.1,4.2 1 0
github.com/x/m/eventstream/b.go:1.1,2.2 9 5
github.com/x/m/eventstream/b.go:3.1,4.2 1 0
`

func TestCoverage(t *testing.T) {
	cov, err := coverage(strings.NewReader(profile))
	if err != nil {
		t.Fatal(err)
	}
	if cov["github.com/x/m/sigv4"] != 75 || cov["github.com/x/m/eventstream"] != 90 {
		t.Fatalf("%v", cov)
	}
	// a planted package under the minimum is reported
	fails, err := check(cov, 90, []string{"sigv4", "eventstream"})
	if err != nil || len(fails) != 1 || !strings.Contains(fails[0], "sigv4") {
		t.Fatalf("%v %v", fails, err)
	}
	// a package missing from the profile is an error, never a pass
	if _, err := check(cov, 90, []string{"nothere"}); err == nil {
		t.Fatal("missing package passed")
	}
}

func TestBadProfile(t *testing.T) {
	for _, in := range []string{"garbage", "a.go:1.1,2.2 x 1", "a.go:1.1,2.2 1 y", "a.go:1.1,2.2 1"} {
		if _, err := coverage(strings.NewReader("mode: set\n" + in + "\n")); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cover.out")
	if err := os.WriteFile(p, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"70", p, "sigv4", "eventstream"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"90", p, "sigv4"}, &out); err == nil {
		t.Fatal("75 passed a 90 gate")
	}
	if err := run([]string{p}, &out); err == nil {
		t.Fatal("usage accepted")
	}
	if err := run([]string{"1", filepath.Join(dir, "nope"), "x"}, &out); err == nil {
		t.Fatal("missing file accepted")
	}
	for _, bad := range []string{"x", "-1", "101"} {
		if err := run([]string{bad, p, "sigv4"}, &out); err == nil {
			t.Fatalf("MIN %q accepted", bad)
		}
	}
	if err := run([]string{"1", p, "bad"}, &out); err == nil {
		t.Fatal("unknown package accepted")
	}
}
