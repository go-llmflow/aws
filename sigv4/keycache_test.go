package sigv4

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// The cached key is the derived key, and a cache entry never serves another
// secret, day, region or service.
func TestCachedSigningKey(t *testing.T) {
	base := Signer{Credentials: Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret-one"}, Region: "eu-west-3", Service: "bedrock"}
	day := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	want := func(s Signer, t time.Time) (k [32]byte) { s.signingKey(&k, t); return k }
	got := func(s Signer, t time.Time) (k [32]byte) { s.cachedSigningKey(&k, t); return k }
	variants := map[string]struct {
		s Signer
		t time.Time
	}{
		"base":                    {base, day},
		"same day, later":         {base, day.Add(13 * time.Hour)},
		"next day":                {base, day.Add(24 * time.Hour)},
		"other secret, same AKID": {Signer{Credentials: Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret-two"}, Region: "eu-west-3", Service: "bedrock"}, day},
		"other region":            {Signer{Credentials: base.Credentials, Region: "eu-central-1", Service: "bedrock"}, day},
		"other service":           {Signer{Credentials: base.Credentials, Region: "eu-west-3", Service: "s3"}, day},
	}
	for round := 0; round < 2; round++ { // the second round is served from the cache
		for name, v := range variants {
			if got(v.s, v.t) != want(v.s, v.t) {
				t.Errorf("round %d, %s: cached key differs from the derived one", round, name)
			}
		}
	}
	a, b := got(base, day), got(variants["other secret, same AKID"].s, day)
	if a == b {
		t.Fatal("two secrets with one access key ID share a key")
	}
}

// The cache stays bounded and correct past its size.
func TestCachedSigningKeyBounded(t *testing.T) {
	day := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	s := Signer{Credentials: Credentials{AccessKeyID: "AKID", SecretAccessKey: "s"}, Region: "r", Service: "x"}
	for i := 0; i < 3*maxCachedKeys; i++ {
		var k, w [32]byte
		d := day.AddDate(0, 0, i)
		s.cachedSigningKey(&k, d)
		s.signingKey(&w, d)
		if k != w {
			t.Fatalf("day %d: wrong key", i)
		}
	}
	keyCache.mu.RLock()
	n := len(keyCache.m)
	keyCache.mu.RUnlock()
	if n > maxCachedKeys {
		t.Fatalf("cache holds %d entries (max %d)", n, maxCachedKeys)
	}
}

// Concurrent signing is safe (run with -race) and every signature is the one
// a fresh derivation gives.
func TestCachedSigningKeyConcurrent(t *testing.T) {
	s := Signer{Credentials: Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, Region: "us-east-1", Service: "bedrock"}
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	sign := func() string {
		r, _ := http.NewRequest("POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/x/invoke", nil)
		if err := s.Sign(r, []byte("{}"), at); err != nil {
			t.Error(err)
		}
		return r.Header.Get("Authorization")
	}
	ref := sign()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if got := sign(); got != ref {
					t.Errorf("signature differs: %s", got)
					return
				}
			}
		}()
	}
	wg.Wait()
}
