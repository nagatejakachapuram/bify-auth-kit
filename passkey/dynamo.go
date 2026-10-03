package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/go-webauthn/webauthn/webauthn"
)

// DynamoAPI is the part of the DynamoDB client DynamoStore uses.
type DynamoAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
}

// DynamoStore keeps passkeys in a portal's single DynamoDB table, using the conventions both BIFY portals
// already share (PK/SK keys, Unix-second times, a "ttl" expiry attribute):
//
//	USER#<id>               PASSKEY#<sha256(credential id)>  the passkey: public credential, label, times
//	INDEX#passkey#<sha256>  OWNER                            which account a credential belongs to (sign-in)
//	PASSKEY-CEREMONY#<id>   STATE                            a started ceremony, deleted when used, expiring
//	SESSION#<token hash>    STATE                            stepUpUntil is set on the portal's own session
type DynamoStore struct {
	DB    DynamoAPI
	Table string
}

const stateSK = "STATE"

func s(value string) types.AttributeValue { return &types.AttributeValueMemberS{Value: value} }
func n(value int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(value, 10)}
}

func str(item map[string]types.AttributeValue, key string) string {
	if value, ok := item[key].(*types.AttributeValueMemberS); ok {
		return value.Value
	}
	return ""
}

func unix(item map[string]types.AttributeValue, key string) time.Time {
	value, ok := item[key].(*types.AttributeValueMemberN)
	if !ok {
		return time.Time{}
	}
	seconds, err := strconv.ParseInt(value.Value, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0).UTC()
}

func passkeyKey(userID string, credentialID []byte) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"PK": s("USER#" + userID), "SK": s("PASSKEY#" + keyOf(credentialID))}
}

func ownerKey(credentialID []byte) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"PK": s("INDEX#passkey#" + keyOf(credentialID)), "SK": s("OWNER")}
}

func conditionFailed(err error) bool {
	var conditional *types.ConditionalCheckFailedException
	var canceled *types.TransactionCanceledException
	return errors.As(err, &conditional) || errors.As(err, &canceled)
}

// ListPasskeys returns every passkey on the account.
func (d DynamoStore) ListPasskeys(ctx context.Context, userID string) ([]StoredPasskey, error) {
	var out []StoredPasskey
	var start map[string]types.AttributeValue
	for {
		page, err := d.DB.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(d.Table),
			KeyConditionExpression:    aws.String("PK = :pk AND begins_with(SK, :prefix)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":pk": s("USER#" + userID), ":prefix": s("PASSKEY#")},
			ConsistentRead:            aws.Bool(true),
			ExclusiveStartKey:         start,
		})
		if err != nil {
			return nil, err
		}
		for _, item := range page.Items {
			credential, err := unmarshalCredential(str(item, "credential"))
			if err != nil {
				return nil, err // unknown credential state must never disable confirmation
			}
			out = append(out, StoredPasskey{Credential: credential, Name: str(item, "name"), CreatedAt: unix(item, "createdAt"), LastUsedAt: unix(item, "lastUsedAt")})
		}
		if len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		start = page.LastEvaluatedKey
	}
}

// PasskeyOwner returns the account a credential is registered to.
func (d DynamoStore) PasskeyOwner(ctx context.Context, credentialID []byte) (string, error) {
	out, err := d.DB.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(d.Table), Key: ownerKey(credentialID), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return "", err
	}
	owner := str(out.Item, "userID")
	if owner == "" {
		return "", ErrNotFound
	}
	return owner, nil
}

// AddPasskey stores a passkey and its owner index together. A credential id can belong to one account
// only, and an account holds at most max passkeys.
func (d DynamoStore) AddPasskey(ctx context.Context, userID string, passkey StoredPasskey, max int) error {
	existing, err := d.ListPasskeys(ctx, userID)
	if err != nil {
		return err
	}
	if len(existing) >= max {
		return ErrLimit
	}
	credential, err := marshalCredential(passkey.Credential)
	if err != nil {
		return err
	}
	record := passkeyKey(userID, passkey.Credential.ID)
	record["kind"] = s("passkey")
	record["userID"] = s(userID)
	record["credential"] = s(credential)
	record["name"] = s(passkey.Name)
	record["createdAt"] = n(passkey.CreatedAt.Unix())
	index := ownerKey(passkey.Credential.ID)
	index["kind"] = s("identity-index")
	index["userID"] = s(userID)
	_, err = d.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(d.Table), Item: record, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Put: &types.Put{TableName: aws.String(d.Table), Item: index, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
	}})
	if conditionFailed(err) {
		return ErrExists
	}
	return err
}

// UpdatePasskeyUse stores the credential's new counter and flags after a sign-in or confirmation.
func (d DynamoStore) UpdatePasskeyUse(ctx context.Context, userID string, credential webauthn.Credential, at time.Time) error {
	raw, err := marshalCredential(credential)
	if err != nil {
		return err
	}
	_, err = d.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(d.Table),
		Key:                       passkeyKey(userID, credential.ID),
		UpdateExpression:          aws.String("SET credential = :credential, lastUsedAt = :at"),
		ConditionExpression:       aws.String("attribute_exists(PK)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":credential": s(raw), ":at": n(at.Unix())},
	})
	if conditionFailed(err) {
		return ErrNotFound // removed while in use: the sign-in is refused
	}
	return err
}

// RenamePasskey relabels a passkey on the account.
func (d DynamoStore) RenamePasskey(ctx context.Context, userID string, credentialID []byte, name string) error {
	_, err := d.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(d.Table),
		Key:                       passkeyKey(userID, credentialID),
		UpdateExpression:          aws.String("SET #name = :name"),
		ConditionExpression:       aws.String("attribute_exists(PK)"),
		ExpressionAttributeNames:  map[string]string{"#name": "name"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":name": s(name)},
	})
	if conditionFailed(err) {
		return ErrNotFound
	}
	return err
}

// DeletePasskey removes a passkey from the account and its owner index together.
func (d DynamoStore) DeletePasskey(ctx context.Context, userID string, credentialID []byte) error {
	_, err := d.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Delete: &types.Delete{TableName: aws.String(d.Table), Key: passkeyKey(userID, credentialID), ConditionExpression: aws.String("attribute_exists(PK)")}},
		{Delete: &types.Delete{TableName: aws.String(d.Table), Key: ownerKey(credentialID), ConditionExpression: aws.String("userID = :user"), ExpressionAttributeValues: map[string]types.AttributeValue{":user": s(userID)}}},
	}})
	if conditionFailed(err) {
		return ErrNotFound
	}
	return err
}

// SaveCeremony stores a started ceremony until it is used or expires.
func (d DynamoStore) SaveCeremony(ctx context.Context, ceremony Ceremony) error {
	data, err := json.Marshal(ceremony.Data)
	if err != nil {
		return err
	}
	_, err = d.DB.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.Table),
		Item: map[string]types.AttributeValue{
			"PK": s("PASSKEY-CEREMONY#" + ceremony.ID), "SK": s(stateSK), "kind": s("passkey-ceremony"),
			"ceremony": s(ceremony.Kind), "userID": s(ceremony.UserID), "sessionKey": s(ceremony.SessionKey),
			"data": s(string(data)), "expiresAt": n(ceremony.ExpiresAt.Unix()), "ttl": n(ceremony.ExpiresAt.Unix()),
		},
		ConditionExpression: aws.String("attribute_not_exists(PK)"),
	})
	return err
}

// TakeCeremony returns a ceremony and deletes it in the same operation, so it can be used once.
func (d DynamoStore) TakeCeremony(ctx context.Context, id string) (Ceremony, error) {
	out, err := d.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:    aws.String(d.Table),
		Key:          map[string]types.AttributeValue{"PK": s("PASSKEY-CEREMONY#" + id), "SK": s(stateSK)},
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return Ceremony{}, err
	}
	if len(out.Attributes) == 0 {
		return Ceremony{}, ErrNotFound
	}
	ceremony := Ceremony{ID: id, Kind: str(out.Attributes, "ceremony"), UserID: str(out.Attributes, "userID"), SessionKey: str(out.Attributes, "sessionKey"), ExpiresAt: unix(out.Attributes, "expiresAt")}
	if err := json.Unmarshal([]byte(str(out.Attributes, "data")), &ceremony.Data); err != nil {
		return Ceremony{}, ErrNotFound
	}
	return ceremony, nil
}

// MarkStepUp records a confirmation on the portal's session record. The session must exist and not be
// revoked.
func (d DynamoStore) MarkStepUp(ctx context.Context, sessionKey string, until time.Time) error {
	_, err := d.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(d.Table),
		Key:                       map[string]types.AttributeValue{"PK": s("SESSION#" + sessionKey), "SK": s(stateSK)},
		UpdateExpression:          aws.String("SET stepUpUntil = :until"),
		ConditionExpression:       aws.String("attribute_exists(PK) AND attribute_not_exists(revokedAt)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":until": n(until.Unix())},
	})
	if conditionFailed(err) {
		return ErrNotFound
	}
	return err
}

// SessionTimes reads when the session was created and until when its last confirmation counts.
func (d DynamoStore) SessionTimes(ctx context.Context, sessionKey string) (time.Time, time.Time, error) {
	out, err := d.DB.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(d.Table), Key: map[string]types.AttributeValue{"PK": s("SESSION#" + sessionKey), "SK": s(stateSK)}, ConsistentRead: aws.Bool(true)})
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if len(out.Item) == 0 {
		return time.Time{}, time.Time{}, ErrNotFound
	}
	return unix(out.Item, "createdAt"), unix(out.Item, "stepUpUntil"), nil
}
