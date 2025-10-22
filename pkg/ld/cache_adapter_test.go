package ld

import (
	"github.com/dgraph-io/ristretto"
	"testing"
	"time"

	jsonld "github.com/piprate/json-gold/ld"
)

func TestRistrettoContextCache_SetGetDel(t *testing.T) {
	c, err := NewRistrettoContextCache(10)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	key := "https://example.com/context"
	rd := &jsonld.RemoteDocument{DocumentURL: key}

	ok := c.Set(key, rd, 1)
	if !ok {
		t.Fatalf("expected Set to return true")
	}
	// Ristretto Set is asynchronous; wait for buffers to flush so Get can observe the value.
	c.c.Wait()

	v, found := c.Get(key)
	if !found {
		t.Fatalf("expected Get to find value")
	}
	rdGot, ok := v.(*jsonld.RemoteDocument)
	if !ok {
		t.Fatalf("Get returned value with wrong type")
	}
	if rdGot.DocumentURL != key {
		t.Fatalf("unexpected document url: %s", rdGot.DocumentURL)
	}

	// Delete and ensure it's gone
	c.Del(key)
	_, found = c.Get(key)
	if found {
		t.Fatalf("expected value to be deleted")
	}
}

func TestRistrettoContextCache_WrongKeyAndValueTypes(t *testing.T) {
	c, err := NewRistrettoContextCache(5)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Non-string key
	if c.Set(123, &jsonld.RemoteDocument{}, 1) {
		t.Fatalf("Set should return false for non-string key")
	}
	if v, ok := c.Get(123); ok || v != nil {
		t.Fatalf("Get should return false for non-string key")
	}

	// Wrong value type
	if c.Set("k", "not a remote document", 1) {
		t.Fatalf("Set should return false for wrong value type")
	}
}

func TestRistrettoContextCache_MaxItemsBehavior(t *testing.T) {
	// Use a small maxItems to exercise evictions; Ristretto is probabilistic, so test gently.
	c, err := NewRistrettoContextCache(2)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	rds := []*jsonld.RemoteDocument{
		{DocumentURL: "a"},
		{DocumentURL: "b"},
		{DocumentURL: "c"},
	}

	// Insert three items with cost 1 each, while capacity is 2. Ristretto may not evict immediately,
	// so we wait a short while and then check that at least one item is present and cache operates.
	for i, rd := range rds {
		ok := c.Set(rd.DocumentURL, rd, 1)
		if !ok {
			t.Fatalf("Set(%d) returned false", i)
		}
		// Ensure the asynchronous set has been applied before continuing.
		c.c.Wait()
	}

	// Allow background eviction/updates to run
	time.Sleep(50 * time.Millisecond)

	// At least one of the keys should be retrievable
	foundAny := false
	for _, rd := range rds {
		if _, ok := c.Get(rd.DocumentURL); ok {
			foundAny = true
			break
		}
	}
	if !foundAny {
		t.Fatalf("expected at least one item to be present in cache after inserts")
	}
}

func TestNewRistrettoContextCacheWithConfig(t *testing.T) {
	cfg := &ristretto.Config[string, *jsonld.RemoteDocument]{
		NumCounters:        10,
		MaxCost:            5,
		BufferItems:        64,
		IgnoreInternalCost: false, // should be set to true by the function
	}
	cache, err := NewRistrettoContextCacheWithConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cache == nil {
		t.Fatal("expected non-nil cache")
	}
	if !cfg.IgnoreInternalCost {
		t.Fatal("expected IgnoreInternalCost to be true")
	}

	// Test basic Set/Get
	key := "test"
	rd := &jsonld.RemoteDocument{DocumentURL: key}
	ok := cache.Set(key, rd, 1)
	if !ok {
		t.Fatal("expected Set to return true")
	}
	cache.c.Wait()
	v, found := cache.Get(key)
	if !found {
		t.Fatal("expected to find value")
	}
	rdGot, ok := v.(*jsonld.RemoteDocument)
	if !ok || rdGot.DocumentURL != key {
		t.Fatal("unexpected value from cache")
	}
}
