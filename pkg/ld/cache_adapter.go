package ld

import (
	"github.com/dgraph-io/ristretto"
	jsonld "github.com/piprate/json-gold/ld"
)

const (
	defaultBufferItems         = 64
	ristrettoCounterMultiplier = 10 // ~10x capacity is a common guideline
)

// RistrettoContextCache adapts the generic Ristretto v2 cache to your non-generic ld.Cache interface.
type RistrettoContextCache struct {
	c *ristretto.Cache[string, *jsonld.RemoteDocument]
}

// NewRistrettoContextCache creates a cache sized by "items" when you use cost=1 per item.
// It sets IgnoreInternalCost=true to preserve your unit-cost semantics.
func NewRistrettoContextCache(maxItems int64) (*RistrettoContextCache, error) {
	cfg := &ristretto.Config[string, *jsonld.RemoteDocument]{
		NumCounters:        maxItems * ristrettoCounterMultiplier,
		MaxCost:            maxItems,
		BufferItems:        defaultBufferItems,
		IgnoreInternalCost: true,
	}
	c, err := ristretto.NewCache[string, *jsonld.RemoteDocument](cfg)
	if err != nil {
		return nil, err
	}
	return &RistrettoContextCache{c: c}, nil
}

// NewRistrettoContextCacheWithConfig lets you provide a full Ristretto v2 config (if you prefer).
func NewRistrettoContextCacheWithConfig(cfg *ristretto.Config[string, *jsonld.RemoteDocument]) (
	*RistrettoContextCache, error) {
	if cfg != nil {
		if !cfg.IgnoreInternalCost {
			cfg.IgnoreInternalCost = true
		}
	}
	c, err := ristretto.NewCache[string, *jsonld.RemoteDocument](cfg)
	if err != nil {
		return nil, err
	}
	return &RistrettoContextCache{c: c}, nil
}

// Ensure RistrettoContextCache satisfies your existing ld.Cache interface.
var _ Cache = (*RistrettoContextCache)(nil)

func (r *RistrettoContextCache) Get(key interface{}) (interface{}, bool) {
	s, ok := key.(string)
	if !ok {
		return nil, false
	}
	v, ok := r.c.Get(s)
	if !ok {
		return nil, false
	}
	return v, true
}

func (r *RistrettoContextCache) Set(key, value interface{}, cost int64) bool {
	s, ok := key.(string)
	if !ok {
		return false
	}
	rd, ok := value.(*jsonld.RemoteDocument)
	if !ok {
		return false
	}
	return r.c.Set(s, rd, cost)
}

func (r *RistrettoContextCache) Del(key interface{}) {
	s, ok := key.(string)
	if !ok {
		return
	}
	r.c.Del(s)
}
