package passkey

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/go-webauthn/webauthn/webauthn"
)

func membershipCredential(id string) StoredPasskey {
	return StoredPasskey{Credential: webauthn.Credential{ID: []byte(id)}, CreatedAt: time.Now()}
}

// Force both writers to count the same nine credentials before either commits.
type simultaneousQueries struct {
	DynamoAPI
	mu        sync.Mutex
	remaining int
	ready     chan struct{}
}

func (b *simultaneousQueries) Query(ctx context.Context, in *dynamodb.QueryInput, opt ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	out, err := b.DynamoAPI.Query(ctx, in, opt...)
	b.mu.Lock()
	wait := b.remaining > 0
	if wait {
		b.remaining--
		if b.remaining == 0 {
			close(b.ready)
		}
	}
	b.mu.Unlock()
	if wait {
		select {
		case <-b.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return out, err
}

func seedLegacyPasskey(t *testing.T, db *fakeDynamo, user, id string) {
	t.Helper()
	p := membershipCredential(id)
	raw, err := marshalCredential(p.Credential)
	if err != nil {
		t.Fatal(err)
	}
	record := passkeyKey(user, p.Credential.ID)
	record["credential"] = s(raw)
	index := ownerKey(p.Credential.ID)
	index["userID"] = s(user)
	db.items[itemKey(record)] = record
	db.items[itemKey(index)] = index
}

func TestConcurrentRegistrationsCannotExceedLimitIncludingLegacyAccounts(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			db := newFakeDynamo(t)
			store := DynamoStore{DB: db, Table: "test"}
			for i := 0; i < 9; i++ {
				id := fmt.Sprintf("key-%d", i)
				if legacy {
					seedLegacyPasskey(t, db, "user", id)
				} else if err := store.AddPasskey(t.Context(), "user", membershipCredential(id), 10); err != nil {
					t.Fatal(err)
				}
			}
			store.DB = &simultaneousQueries{DynamoAPI: db, remaining: 2, ready: make(chan struct{})}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			results := make(chan error, 2)
			for i := 0; i < 2; i++ {
				go func() { results <- store.AddPasskey(ctx, "user", membershipCredential(fmt.Sprintf("new-%d", i)), 10) }()
			}
			success, limited := 0, 0
			for i := 0; i < 2; i++ {
				err := <-results
				if err == nil {
					success++
				} else if errors.Is(err, ErrLimit) {
					limited++
				} else {
					t.Fatal(err)
				}
			}
			keys, err := store.ListPasskeys(ctx, "user")
			if err != nil || len(keys) != 10 || success != 1 || limited != 1 {
				t.Fatalf("keys=%d success=%d limited=%d err=%v", len(keys), success, limited, err)
			}
			if err := store.DeletePasskey(ctx, "user", keys[0].Credential.ID); err != nil {
				t.Fatal(err)
			}
			if err := store.AddPasskey(ctx, "user", membershipCredential("replacement"), 10); err != nil {
				t.Fatal(err)
			}
			keys, _ = store.ListPasskeys(ctx, "user")
			if len(keys) != 10 {
				t.Fatalf("replacement left %d credentials", len(keys))
			}
		})
	}
}

func TestMembershipRevisionSurvivesLastDeletion(t *testing.T) {
	db := newFakeDynamo(t)
	store := DynamoStore{DB: db, Table: "test"}
	if err := store.AddPasskey(t.Context(), "user", membershipCredential("key"), 10); err != nil {
		t.Fatal(err)
	}
	before := str(db.items[itemKey(membershipKey("user"))], "revision")
	if err := store.DeletePasskey(t.Context(), "user", []byte("key")); err != nil {
		t.Fatal(err)
	}
	after := str(db.items[itemKey(membershipKey("user"))], "revision")
	if before == "" || after == "" || before == after {
		t.Fatal("membership revision was removed or reused")
	}
}

type canceledMembership struct {
	DynamoAPI
	calls  int
	reason string
}

func (d *canceledMembership) TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	d.calls++
	return nil, &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{
		{Code: aws.String("None")}, {Code: aws.String("None")}, {Code: aws.String(d.reason)},
	}}
}

func TestMembershipConflictsAreBoundedAndStorageErrorsStayErrors(t *testing.T) {
	for _, reason := range []string{"TransactionConflict", "ConditionalCheckFailed", "ProvisionedThroughputExceeded", "ValidationError"} {
		t.Run(reason, func(t *testing.T) {
			db := &canceledMembership{DynamoAPI: newFakeDynamo(t), reason: reason}
			store := DynamoStore{DB: db, Table: "test"}
			err := store.AddPasskey(t.Context(), "user", membershipCredential("key"), 10)
			if err == nil || errors.Is(err, ErrExists) || errors.Is(err, ErrLimit) {
				t.Fatalf("storage error misclassified: %v", err)
			}
			want := 1
			if reason == "TransactionConflict" || reason == "ConditionalCheckFailed" {
				want = membershipAttempts
			}
			if db.calls != want {
				t.Fatalf("calls = %d, want %d", db.calls, want)
			}
		})
	}
}
