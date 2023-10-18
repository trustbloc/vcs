/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

This file contains software code that is the intellectual property of SecureKey.
*/

package locker

import (
	"context"
	"sync"

	"github.com/go-redsync/redsync/v4"
)

// KeyedMutexLocker is a mutex locker that locks based on a key.
type KeyedMutexLocker struct {
	mu      sync.Mutex
	mutexes map[string]*sync.Mutex
}

// NewKeyedMutex creates a new mutex locker.
func NewKeyedMutex() *KeyedMutexLocker {
	return &KeyedMutexLocker{
		mutexes: make(map[string]*sync.Mutex),
	}
}

// Lock is a mutex that locks based on a key.
type Lock interface {
	LockContext(ctx context.Context) error
	UnlockContext(ctx context.Context) (bool, error)
	Unlock() (bool, error)
}

// NewMutex creates a new mutex.
func (k *KeyedMutexLocker) NewMutex(key string, _ ...redsync.Option) Lock {
	k.mu.Lock()
	if _, ok := k.mutexes[key]; !ok {
		k.mutexes[key] = &sync.Mutex{}
	}
	mu := k.mutexes[key]
	k.mu.Unlock()

	return &KeyedMutex{
		Mut: mu,
	}
}

// KeyedMutex is a mutex that locks based on a key.
type KeyedMutex struct {
	Mut *sync.Mutex
}

// LockContext locks the mutex.
func (k *KeyedMutex) LockContext(_ context.Context) error {
	k.Mut.Lock()
	return nil
}

// UnlockContext unlocks the mutex.
func (k *KeyedMutex) UnlockContext(_ context.Context) (bool, error) {
	return k.Unlock()
}

// Unlock unlocks the mutex.
func (k *KeyedMutex) Unlock() (bool, error) {
	k.Mut.Unlock()

	return true, nil
}
