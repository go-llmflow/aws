// Command covercheck fails unless every named package of a Go coverprofile
// is covered at least -min percent:
//
//	go run ./internal/covercheck 90 cover.out sigv4 eventstream
//
// Package names are directories relative to the module root.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
)

// coverage returns the statement coverage percentage per directory.
func coverage(r io.Reader) (map[string]float64, error) {
	total, hit := map[string]int{}, map[string]int{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}
		// name.go:l.c,l.c numStmts count
		i := strings.LastIndexByte(line, ':')
		if i < 0 {
			return nil, fmt.Errorf("bad line %q", line)
		}
		f := strings.Fields(line[i+1:])
		if len(f) != 3 {
			return nil, fmt.Errorf("bad line %q", line)
		}
		n, err1 := strconv.Atoi(f[1])
		c, err2 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("bad line %q", line)
		}
		dir := path.Dir(line[:i])
		total[dir] += n
		if c > 0 {
			hit[dir] += n
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := map[string]float64{}
	for d, n := range total {
		out[d] = 100 * float64(hit[d]) / float64(n)
	}
	return out, nil
}

// check returns the packages (by suffix of the directory) under min, and an
// error for one that does not appear at all: a gate that reads nothing must
// not pass.
func check(cov map[string]float64, min float64, pkgs []string) (failures []string, err error) {
	for _, p := range pkgs {
		found := false
		for d, pct := range cov {
			if d == p || strings.HasSuffix(d, "/"+p) {
				found = true
				fmt.Printf("%-40s %5.1f%%\n", d, pct)
				if pct < min {
					failures = append(failures, fmt.Sprintf("%s: %.1f%% < %.1f%%", d, pct, min))
				}
			}
		}
		if !found {
			return nil, fmt.Errorf("package %q is not in the profile", p)
		}
	}
	return failures, nil
}

func run(args []string, stdout io.Writer) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: covercheck MIN-PERCENT PROFILE PACKAGE...")
	}
	min, err := strconv.ParseFloat(args[0], 64)
	if err != nil || min < 0 || min > 100 {
		return fmt.Errorf("MIN-PERCENT %q: want a number from 0 to 100", args[0])
	}
	f, err := os.Open(args[1])
	if err != nil {
		return err
	}
	defer f.Close()
	cov, err := coverage(f)
	if err != nil {
		return err
	}
	fails, err := check(cov, min, args[2:])
	if err != nil {
		return err
	}
	if len(fails) > 0 {
		return fmt.Errorf("coverage below minimum:\n%s", strings.Join(fails, "\n"))
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
