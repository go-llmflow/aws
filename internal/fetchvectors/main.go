// Command fetchvectors vendors the aws-c-auth SigV4 test suite into
// sigv4/testdata/v4 at a pinned commit. Run from the repository root:
//
//	go run ./internal/fetchvectors
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const (
	commit = "3d29adcecf5c032131acee9f4125a636d2aaea6a"
	api    = "https://api.github.com/repos/awslabs/aws-c-auth/contents/tests/aws-signing-test-suite/v4"
	raw    = "https://raw.githubusercontent.com/awslabs/aws-c-auth/" + commit + "/tests/aws-signing-test-suite/v4/"
)

var files = []string{"request.txt", "context.json", "header-canonical-request.txt", "header-string-to-sign.txt", "header-signature.txt"}

func get(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func run() error {
	b, err := get(api + "?ref=" + commit)
	if err != nil {
		return err
	}
	var entries []struct{ Name, Type string }
	if err := json.Unmarshal(b, &entries); err != nil {
		return err
	}
	out := filepath.Join("sigv4", "testdata", "v4")
	n := 0
	for _, e := range entries {
		if e.Type != "dir" {
			continue
		}
		if err := os.MkdirAll(filepath.Join(out, e.Name), 0o755); err != nil {
			return err
		}
		for _, f := range files {
			data, err := get(raw + e.Name + "/" + f)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(out, e.Name, f), data, 0o644); err != nil {
				return err
			}
		}
		n++
	}
	lic, err := get("https://raw.githubusercontent.com/awslabs/aws-c-auth/" + commit + "/LICENSE")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join("sigv4", "testdata", "LICENSE"), lic, 0o644); err != nil {
		return err
	}
	fmt.Println("vendored", n, "cases")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
