package locker_test

import (
	"context"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/locker"
)

func TestKeyedMutexLocker_NewMutex(t *testing.T) {
	km := locker.NewKeyedMutex()

	key := "test"
	m1 := km.NewMutex(key).(*locker.KeyedMutex)
	assert.NotNil(t, m1)
	// Retrieving the same key should return the same mutex
	m2 := km.NewMutex(key).(*locker.KeyedMutex)
	assert.Same(t, m1.Mut, m2.Mut)

	// Retrieving a different key should return a different mutex
	m3 := km.NewMutex("test2").(*locker.KeyedMutex)
	assert.NotSame(t, m1.Mut, m3.Mut)
}

func TestKeyedMutex_LockAndUnlock(t *testing.T) {
	km := locker.NewKeyedMutex()

	key := "lock_test"
	mutex := km.NewMutex(key)

	// Testing the lock and unlock mechanism
	ctx := context.Background()
	err := mutex.LockContext(ctx)
	if err != nil {
		t.Errorf("failed to lock the mutex: %v", err)
	}

	var mut2LockAcquiredTime *time.Time
	go func() {
		mutex2 := km.NewMutex(key)

		assert.NoError(t, mutex2.LockContext(context.TODO()))
		mut2LockAcquiredTime = lo.ToPtr(time.Now())
	}()

	time.Sleep(2 * time.Second)
	unlockTime := time.Now()
	ok, err := mutex.UnlockContext(ctx)
	assert.True(t, ok)
	assert.NoError(t, err)
	time.Sleep(1 * time.Second)

	assert.True(t, mut2LockAcquiredTime.After(unlockTime))
}
