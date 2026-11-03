package sigv4

import (
	"hash/maphash"
	"sync"
	"time"
)

// The signing key depends only on the secret, the day, the region and the
// service, so it is derived once per day rather than on every request (four
// HMAC-SHA256 calls, eight SHA-256 blocks). aws-sdk-go-v2 does the same
// (aws/signer/internal/v4/cache.go: a map keyed by region/service, checked
// against the access key ID and the day). This cache is stricter: an entry
// is keyed by a hash of the secret as well, so two credentials sharing an
// access key ID never share a key, and it is bounded. It holds derived keys
// only, never a secret.
//
// The secret's hash is hash/maphash with a seed drawn once per process: a
// few nanoseconds, where the SHA-256 of v0.1.1 cost about one block per
// request and left signing 1.7 % slower than the SDK (go-llmflow/aws
// _bench, abbench, 10 alternating rounds at load <= 4, 2026-11-03). The
// hash only has to tell this process's secrets apart, and the seed is
// never exposed, so a 64-bit collision between two of them (2^-64 per pair)
// is the only way to share an entry.

const maxCachedKeys = 256

type keyCacheKey struct {
	secret          uint64 // maphash of the secret, process-local seed
	day             int32  // YYYYMMDD (UTC)
	region, service string
}

var (
	keySeed  = maphash.MakeSeed()
	keyCache struct {
		mu sync.RWMutex
		m  map[keyCacheKey][32]byte
	}
)

// cachedSigningKey returns the signing key of s for the day of t, deriving
// and caching it on a miss.
func (s Signer) cachedSigningKey(dst *[32]byte, t time.Time) {
	y, m, d := t.UTC().Date()
	k := keyCacheKey{
		secret:  maphash.String(keySeed, s.SecretAccessKey),
		day:     int32(y*10000 + int(m)*100 + d),
		region:  s.Region,
		service: s.Service,
	}
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
