package passkey

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const membershipAttempts = 8

// A persistent revision serializes all changes to an account's credential set.
// Read it BEFORE counting credentials, then replace it in the same transaction
// as the credential and owner index. This also counts legacy credentials without
// a counter backfill. Never delete this record: that would allow an ABA race.
// All writers must use this protocol; drain old application versions on rollout.
func membershipKey(userID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"PK": s("USER#" + userID), "SK": s("PASSKEY-MEMBERSHIP")}
}

func (d DynamoStore) membershipWrite(ctx context.Context, userID string) (types.TransactWriteItem, error) {
	key := membershipKey(userID)
	out, err := d.DB.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(d.Table), Key: key, ConsistentRead: aws.Bool(true)})
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	condition := "attribute_not_exists(PK)"
	var values map[string]types.AttributeValue
	if len(out.Item) != 0 {
		revision := str(out.Item, "revision")
		if revision == "" {
			return types.TransactWriteItem{}, errors.New("passkey: invalid membership revision")
		}
		condition = "revision = :previous"
		values = map[string]types.AttributeValue{":previous": s(revision)}
	}
	revision, err := randomID()
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	key["revision"] = s(revision)
	key["kind"] = s("passkey-membership")
	return types.TransactWriteItem{Put: &types.Put{
		TableName: aws.String(d.Table), Item: key,
		ConditionExpression: aws.String(condition), ExpressionAttributeValues: values,
	}}, nil
}

// Classify only known cancellation reasons. Throttling, validation failures and
// outages must not be mislabeled as duplicate or missing credentials.
func membershipCancellation(err error) (credentialConflict, retry bool) {
	var canceled *types.TransactionCanceledException
	if !errors.As(err, &canceled) || len(canceled.CancellationReasons) != 3 {
		return false, false
	}
	for i, reason := range canceled.CancellationReasons {
		switch aws.ToString(reason.Code) {
		case "None", "":
		case "ConditionalCheckFailed":
			if i < 2 {
				credentialConflict = true
			} else {
				retry = true
			}
		case "TransactionConflict":
			retry = true
		default:
			return false, false
		}
	}
	return credentialConflict, retry
}

func membershipBackoff(ctx context.Context, attempt int) error {
	delay := time.Duration(rand.Int64N(int64(time.Millisecond * time.Duration(1<<attempt))))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// AddPasskey atomically enforces account capacity and unique credential ownership.
func (d DynamoStore) AddPasskey(ctx context.Context, userID string, passkey StoredPasskey, max int) error {
	raw, err := marshalCredential(passkey.Credential)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < membershipAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		membership, err := d.membershipWrite(ctx, userID)
		if err != nil {
			return err
		}
		existing, err := d.ListPasskeys(ctx, userID)
		if err != nil {
			return err
		}
		if len(existing) >= max {
			return ErrLimit
		}
		record := passkeyKey(userID, passkey.Credential.ID)
		record["kind"], record["userID"] = s("passkey"), s(userID)
		record["credential"], record["name"] = s(raw), s(passkey.Name)
		record["createdAt"] = n(passkey.CreatedAt.Unix())
		index := ownerKey(passkey.Credential.ID)
		index["kind"], index["userID"] = s("identity-index"), s(userID)
		_, err = d.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{TableName: aws.String(d.Table), Item: record, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
			{Put: &types.Put{TableName: aws.String(d.Table), Item: index, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
			membership,
		}})
		if err == nil {
			return nil
		}
		conflict, retry := membershipCancellation(err)
		if conflict {
			return ErrExists
		}
		if !retry || attempt == membershipAttempts-1 {
			return err
		}
		if err := membershipBackoff(ctx, attempt); err != nil {
			return err
		}
	}
	panic("unreachable")
}

// DeletePasskey changes membership in the same transaction as both deletions, so
// racing registration counts cannot commit against a stale credential set.
func (d DynamoStore) DeletePasskey(ctx context.Context, userID string, credentialID []byte) error {
	for attempt := 0; attempt < membershipAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		membership, err := d.membershipWrite(ctx, userID)
		if err != nil {
			return err
		}
		_, err = d.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
			{Delete: &types.Delete{TableName: aws.String(d.Table), Key: passkeyKey(userID, credentialID), ConditionExpression: aws.String("attribute_exists(PK)")}},
			{Delete: &types.Delete{TableName: aws.String(d.Table), Key: ownerKey(credentialID), ConditionExpression: aws.String("userID = :user"), ExpressionAttributeValues: map[string]types.AttributeValue{":user": s(userID)}}},
			membership,
		}})
		if err == nil {
			return nil
		}
		conflict, retry := membershipCancellation(err)
		if conflict {
			return ErrNotFound
		}
		if !retry || attempt == membershipAttempts-1 {
			return err
		}
		if err := membershipBackoff(ctx, attempt); err != nil {
			return err
		}
	}
	panic("unreachable")
}
