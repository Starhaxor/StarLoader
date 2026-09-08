package integration_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/starloader/backend/internal/store"
)

func TestDPoPReplayHasOneWinnerAcrossStoreInstances(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := openTestPool(t, ctx)
	resetAndMigrate(t, ctx, pool)
	var winners atomic.Int32
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ok, err := store.New(pool).ConsumeDPoP(ctx, [32]byte{1}, time.Now().Add(10*time.Minute))
			if err != nil {
				t.Error(err)
			}
			if ok {
				winners.Add(1)
			}
		}()
	}
	workers.Wait()
	if winners.Load() != 1 {
		t.Fatalf("proof admitted %d times", winners.Load())
	}
	ok, err := store.New(pool).ConsumeDPoP(ctx, [32]byte{1}, time.Now().Add(10*time.Minute))
	if err != nil || ok {
		t.Fatalf("persisted replay admitted: %t %v", ok, err)
	}
}
