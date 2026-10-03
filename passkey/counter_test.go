package passkey

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/go-webauthn/webauthn/webauthn"
)

func counterCredential(count uint32) webauthn.Credential {
	return webauthn.Credential{ID: []byte("counter-key"), Authenticator: webauthn.Authenticator{SignCount: count}}
}

func counterStores(t *testing.T, count uint32) map[string]Store {
	t.Helper()
	m := NewMemoryStore()
	if err := m.AddPasskey(t.Context(), "user", StoredPasskey{Credential: counterCredential(count)}, 10); err != nil {
		t.Fatal(err)
	}
	db := newFakeDynamo(t)
	record := passkeyKey("user", counterCredential(count).ID)
	raw, err := marshalCredential(counterCredential(count))
	if err != nil {
		t.Fatal(err)
	}
	record["credential"] = s(raw)
	db.items[itemKey(record)] = record // Existing records need no migration or version attribute.
	return map[string]Store{"memory": m, "dynamo": DynamoStore{DB: db, Table: "test"}}
}

func TestCounterPersistenceRejectsStaleAssertions(t *testing.T) {
	for name, store := range counterStores(t, 1) {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			if err := store.UpdatePasskeyUse(t.Context(), "user", counterCredential(3), now); err != nil {
				t.Fatal(err)
			}
			for _, count := range []uint32{2, 3, 0} {
				if err := store.UpdatePasskeyUse(t.Context(), "user", counterCredential(count), now); !errors.Is(err, ErrVerification) {
					t.Fatalf("count %d: %v", count, err)
				}
			}
			list, err := store.ListPasskeys(t.Context(), "user")
			if err != nil || list[0].Credential.Authenticator.SignCount != 3 {
				t.Fatalf("stored = %+v, %v", list, err)
			}
		})
	}
}

func TestCounterPersistenceConcurrentDuplicateAndCounterless(t *testing.T) {
	for _, next := range []uint32{0, 1} {
		for name, store := range counterStores(t, 0) {
			t.Run(name+string(rune('0'+next)), func(t *testing.T) {
				start := make(chan struct{})
				results := make(chan error, 2)
				for i := 0; i < 2; i++ {
					go func() {
						<-start
						results <- store.UpdatePasskeyUse(t.Context(), "user", counterCredential(next), time.Now())
					}()
				}
				close(start)
				successes := 0
				for i := 0; i < 2; i++ {
					err := <-results
					if err == nil {
						successes++
					} else if !errors.Is(err, ErrVerification) {
						t.Fatal(err)
					}
				}
				want := 1
				if next == 0 {
					want = 2
				}
				if successes != want {
					t.Fatalf("successful updates = %d, want %d", successes, want)
				}
			})
		}
	}
}

// Both readers observe counter 1, then counter 3 commits before the assertion with counter 2.
// The loser must retry its read and reject 2 instead of resetting the persisted counter to 2.
type orderedCounterDynamo struct {
	*fakeDynamo
	reads    atomic.Int32
	ready    sync.WaitGroup
	highDone chan struct{}
}

func (d *orderedCounterDynamo) GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if in.ConsistentRead == nil || !*in.ConsistentRead {
		d.t.Error("counter read must be strongly consistent")
	}
	out, err := d.fakeDynamo.GetItem(ctx, in, opts...)
	if d.reads.Add(1) <= 2 {
		d.ready.Done()
		d.ready.Wait()
	}
	return out, err
}
func (d *orderedCounterDynamo) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	credential, err := unmarshalCredential(str(in.ExpressionAttributeValues, ":credential"))
	if err != nil {
		return nil, err
	}
	if credential.Authenticator.SignCount == 2 {
		<-d.highDone
	}
	out, err := d.fakeDynamo.UpdateItem(ctx, in, opts...)
	if credential.Authenticator.SignCount == 3 {
		close(d.highDone)
	}
	return out, err
}
func TestDynamoCounterCASRejectsOutOfOrderConcurrentAssertion(t *testing.T) {
	store := counterStores(t, 1)["dynamo"].(DynamoStore)
	db := &orderedCounterDynamo{fakeDynamo: store.DB.(*fakeDynamo), highDone: make(chan struct{})}
	db.ready.Add(2)
	store.DB = db
	results := make(chan error, 2)
	for _, count := range []uint32{2, 3} {
		go func(count uint32) {
			results <- store.UpdatePasskeyUse(t.Context(), "user", counterCredential(count), time.Now())
		}(count)
	}
	failures := 0
	for i := 0; i < 2; i++ {
		if err := <-results; errors.Is(err, ErrVerification) {
			failures++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if failures != 1 {
		t.Fatalf("stale assertion failures = %d", failures)
	}
	list, err := store.ListPasskeys(t.Context(), "user")
	if err != nil || list[0].Credential.Authenticator.SignCount != 3 {
		t.Fatalf("stored = %+v, %v", list, err)
	}
	if db.reads.Load() != 3 {
		t.Fatalf("CAS loser did not re-read latest credential: %d reads", db.reads.Load())
	}
}

type conflictCounterDynamo struct {
	*fakeDynamo
	attempts int
	remove   bool
}

func (d *conflictCounterDynamo) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	d.attempts++
	if d.remove {
		d.mu.Lock()
		delete(d.items, itemKey(in.Key))
		d.mu.Unlock()
	}
	return nil, &types.ConditionalCheckFailedException{}
}
func TestDynamoCounterCASDeletionAndBoundedContention(t *testing.T) {
	for _, remove := range []bool{false, true} {
		store := counterStores(t, 1)["dynamo"].(DynamoStore)
		db := &conflictCounterDynamo{fakeDynamo: store.DB.(*fakeDynamo), remove: remove}
		store.DB = db
		err := store.UpdatePasskeyUse(t.Context(), "user", counterCredential(2), time.Now())
		if err == nil {
			t.Fatal("uncommitted credential accepted")
		}
		if remove && (!errors.Is(err, ErrNotFound) || db.attempts != 1) {
			t.Fatalf("revoked credential: %v, attempts %d", err, db.attempts)
		}
		if !remove && db.attempts != 8 {
			t.Fatalf("unbounded/unexpected retries: %d", db.attempts)
		}
	}
}
