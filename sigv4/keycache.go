package sigv4

import (
	"crypto/sha256"
	"sync"
	"time"
)

// The signing key depends only on the secret, the day, the region and the
// service, so it is derived once per day rather than on every request (four
// HMAC-SHA256 calls, eight SHA-256 blocks). aws-sdk-go-v2 does the same
// (aws/signer/internal/v4/cache.go: a map keyed by region/service, checked
// against the access key ID and the day). This cache is stricter: an entry
// is keyed by a SHA-256 of the secret as well, so two credentials sharing an
// access key ID never share a key, and it is bounded. It holds derived keys
// only, never a secret.

const maxCachedKeys = 256

type keyCacheKey struct {
	secret                [32]byte // SHA-256 of "AWS4"+secret
	date, region, service string
}

var keyCache struct {
	mu sync.RWMutex
	m  map[keyCacheKey][32]byte
}

// cachedSigningKey returns the signing key of s for the day of t, deriving
// and caching it on a miss.
func (s Signer) cachedSigningKey(dst *[32]byte, t time.Time) {
	var kb [64]byte
	seed := append(kb[:0], "AWS4"...)
	seed = append(seed, s.SecretAccessKey...)
	k := keyCacheKey{secret: sha256.Sum256(seed), date: t.UTC().Format(dateFormat), region: s.Region, service: s.Service}
	keyCache.mu.RLock()
	v, ok := keyCache.m[k]
	keyCache.mu.RUnlock()
	if ok {
		*dst = v
		return
	}
	s.signingKey(dst, t)
	keyCache.mu.Lock()
	if keyCache.m == nil || len(keyCache.m) >= maxCachedKeys {
		keyCache.m = make(map[keyCacheKey][32]byte)
	}
	keyCache.m[k] = *dst
	keyCache.mu.Unlock()
}
