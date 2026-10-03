package passkey

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/nagatejakachapuram/bify-auth-kit/passkeytest"
)

// fakeDynamo evaluates exactly the expressions DynamoStore sends, so the store's conditions (single-use
// ceremonies, one owner per credential, owner-checked deletes, no step-up on revoked sessions) are
// tested as written. An expression it does not understand fails the test.
type fakeDynamo struct {
	t     *testing.T
	mu    sync.Mutex
	items map[string]map[string]types.AttributeValue
}

func newFakeDynamo(t *testing.T) *fakeDynamo {
	return &fakeDynamo{t: t, items: map[string]map[string]types.AttributeValue{}}
}

func TestUnreadablePasskeyDoesNotDisableConfirmation(t *testing.T) {
	db := newFakeDynamo(t)
	key := passkeyKey("user-a", []byte("credential"))
	key["credential"] = s("invalid-json")
	db.items[itemKey(key)] = key
	store := DynamoStore{DB: db, Table: "test"}
	if _, err := store.ListPasskeys(t.Context(), "user-a"); err == nil {
		t.Fatal("unreadable passkey was treated as an account with no passkeys")
	}
}

func itemKey(key map[string]types.AttributeValue) string {
	return str(key, "PK") + "|" + str(key, "SK")
}

func clone(item map[string]types.AttributeValue) map[string]types.AttributeValue {
	out := map[string]types.AttributeValue{}
	for k, v := range item {
		out[k] = v
	}
	return out
}

var (
	reNotExists = regexp.MustCompile(`^attribute_not_exists\((\w+)\)$`)
	reExists    = regexp.MustCompile(`^attribute_exists\((\w+)\)$`)
	reEquals    = regexp.MustCompile(`^(\w+) = (:\w+)$`)
)

func (f *fakeDynamo) check(expr *string, item map[string]types.AttributeValue, values map[string]types.AttributeValue) bool {
	if expr == nil {
		return true
	}
	for _, clause := range strings.Split(*expr, " AND ") {
		clause = strings.TrimSpace(clause)
		switch {
		case reNotExists.MatchString(clause):
			if item[reNotExists.FindStringSubmatch(clause)[1]] != nil {
				return false
			}
		case reExists.MatchString(clause):
			if item[reExists.FindStringSubmatch(clause)[1]] == nil {
				return false
			}
		case reEquals.MatchString(clause):
			m := reEquals.FindStringSubmatch(clause)
			if item == nil || str(item, m[1]) != str(values, m[2]) {
				return false
			}
		default:
			f.t.Fatalf("fakeDynamo: unsupported condition %q", clause)
		}
	}
	return true
}

func (f *fakeDynamo) apply(item map[string]types.AttributeValue, expr string, names map[string]string, values map[string]types.AttributeValue) {
	if !strings.HasPrefix(expr, "SET ") {
		f.t.Fatalf("fakeDynamo: unsupported update %q", expr)
	}
	for _, assignment := range strings.Split(strings.TrimPrefix(expr, "SET "), ",") {
		parts := strings.SplitN(strings.TrimSpace(assignment), " = ", 2)
		name := parts[0]
		if real, ok := names[name]; ok {
			name = real
		}
		item[name] = values[strings.TrimSpace(parts[1])]
	}
}

func (f *fakeDynamo) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &dynamodb.GetItemOutput{Item: clone(f.items[itemKey(in.Key)])}, nil
}

func (f *fakeDynamo) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.check(in.ConditionExpression, f.items[itemKey(in.Item)], in.ExpressionAttributeValues) {
		return nil, &types.ConditionalCheckFailedException{}
	}
	f.items[itemKey(in.Item)] = clone(in.Item)
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDynamo) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := itemKey(in.Key)
	if !f.check(in.ConditionExpression, f.items[key], in.ExpressionAttributeValues) {
		return nil, &types.ConditionalCheckFailedException{}
	}
	item := clone(f.items[key])
	for k, v := range in.Key {
		item[k] = v
	}
	f.apply(item, *in.UpdateExpression, in.ExpressionAttributeNames, in.ExpressionAttributeValues)
	f.items[key] = item
	return &dynamodb.UpdateItemOutput{}, nil
}

func (f *fakeDynamo) DeleteItem(_ context.Context, in *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := itemKey(in.Key)
	old := f.items[key]
	delete(f.items, key)
	out := &dynamodb.DeleteItemOutput{}
	if in.ReturnValues == types.ReturnValueAllOld {
		out.Attributes = old
	}
	return out, nil
}

func (f *fakeDynamo) TransactWriteItems(_ context.Context, in *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, item := range in.TransactItems {
		switch {
		case item.Put != nil:
			if !f.check(item.Put.ConditionExpression, f.items[itemKey(item.Put.Item)], item.Put.ExpressionAttributeValues) {
				return nil, &types.TransactionCanceledException{}
			}
		case item.Delete != nil:
			if !f.check(item.Delete.ConditionExpression, f.items[itemKey(item.Delete.Key)], item.Delete.ExpressionAttributeValues) {
				return nil, &types.TransactionCanceledException{}
			}
		default:
			f.t.Fatal("fakeDynamo: unsupported transaction item")
		}
	}
	for _, item := range in.TransactItems {
		if item.Put != nil {
			f.items[itemKey(item.Put.Item)] = clone(item.Put.Item)
		} else {
			delete(f.items, itemKey(item.Delete.Key))
		}
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func (f *fakeDynamo) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if *in.KeyConditionExpression != "PK = :pk AND begins_with(SK, :prefix)" {
		f.t.Fatalf("fakeDynamo: unsupported query %q", *in.KeyConditionExpression)
	}
	pk, prefix := str(in.ExpressionAttributeValues, ":pk"), str(in.ExpressionAttributeValues, ":prefix")
	out := &dynamodb.QueryOutput{}
	for _, item := range f.items {
		if str(item, "PK") == pk && strings.HasPrefix(str(item, "SK"), prefix) {
			out.Items = append(out.Items, clone(item))
		}
	}
	return out, nil
}

func (f *fakeDynamo) session(key string, created time.Time, revoked bool) {
	item := map[string]types.AttributeValue{"PK": s("SESSION#" + key), "SK": s(stateSK), "createdAt": n(created.Unix())}
	if revoked {
		item["revokedAt"] = n(created.Unix())
	}
	f.items[itemKey(item)] = item
}

func TestDynamoStoreRunsTheWholeLifecycle(t *testing.T) {
	db := newFakeDynamo(t)
	store := DynamoStore{DB: db, Table: "portal"}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	cfg, _ := ConfigFromOrigin(testOrigin, "BIFY Account")
	cfg.Now = func() time.Time { return now }
	svc, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	user := User{ID: "7c9e6679-7425-40de-944b-e07fc1f90ae7", Name: "buyer@example.com"}
	db.session("old", now.Add(-time.Hour), false)
	db.session("revoked", now.Add(-time.Hour), true)
	ctx := context.Background()

	a := passkeytest.NewAuthenticator(t, testRP, testOrigin)
	id, creation, err := svc.BeginRegistration(ctx, user, "old")
	if err != nil {
		t.Fatal(err)
	}
	passkey, err := svc.FinishRegistration(ctx, user, "old", id, "MacBook", a.Register(t, creation))
	if err != nil {
		t.Fatal(err)
	}
	if owner, err := store.PasskeyOwner(ctx, a.ID); err != nil || owner != user.ID {
		t.Fatalf("owner index = %q, %v", owner, err)
	}
	// A second account cannot claim the same credential.
	if err := store.AddPasskey(ctx, "someone-else", StoredPasskey{Credential: mustCredential(t, store, user.ID), Name: "x", CreatedAt: now}, 10); !errors.Is(err, ErrExists) {
		t.Fatalf("claiming another account's credential = %v", err)
	}

	id, assertion, _ := svc.BeginLogin(ctx)
	if owner, err := svc.FinishLogin(ctx, id, a.Assert(t, assertion)); err != nil || owner != user.ID {
		t.Fatalf("sign-in = %q, %v", owner, err)
	}
	if _, err := store.TakeCeremony(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a used ceremony is still stored: %v", err)
	}

	id, assertion, _ = svc.BeginStepUp(ctx, user, "old")
	if err := svc.FinishStepUp(ctx, user, "old", id, a.Assert(t, assertion)); err != nil {
		t.Fatal(err)
	}
	if recent, _ := svc.RecentlyAuthenticated(ctx, "old"); !recent {
		t.Fatal("confirmation not recorded on the session")
	}
	if err := store.MarkStepUp(ctx, "revoked", now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("confirming a revoked session = %v", err)
	}

	if err := svc.Rename(ctx, user.ID, passkey.ID, "Work MacBook"); err != nil {
		t.Fatal(err)
	}
	list, _ := svc.List(ctx, user.ID)
	if len(list) != 1 || list[0].Name != "Work MacBook" || list[0].LastUsedAt == nil {
		t.Fatalf("list = %+v", list)
	}
	if err := svc.Delete(ctx, "someone-else", passkey.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting another account's passkey = %v", err)
	}
	if err := svc.Delete(ctx, user.ID, passkey.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PasskeyOwner(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("owner index survived the delete: %v", err)
	}
}

func mustCredential(t *testing.T, store DynamoStore, userID string) (credential webauthn.Credential) {
	t.Helper()
	list, err := store.ListPasskeys(context.Background(), userID)
	if err != nil || len(list) == 0 {
		t.Fatalf("no passkey to copy: %v", err)
	}
	return list[0].Credential
}
