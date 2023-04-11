/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongo

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type genericDocument[T any] struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Record   T                  `bson:"record"`
	LookupID string             `bson:"_lookupId"`
	ExpireAt *time.Time         `bson:"expireAt,omitempty"`
}
