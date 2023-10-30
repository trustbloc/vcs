/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongo

import (
	"context"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
	"github.com/trustbloc/vcs/pkg/oauth2client"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/clientmanager"
)

func TestAccessTokenFlow(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, mongoErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, mongoErr)

	clientManager, storeErr := clientmanager.NewStore(context.Background(), client)
	assert.NoError(t, storeErr)

	testCases := []struct {
		name      string
		useRevoke bool
	}{
		{
			name:      "use delete",
			useRevoke: false,
		},
		{
			name:      "use revoke",
			useRevoke: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			s, err := NewStore(context.Background(), client, clientManager)
			assert.NoError(t, err)

			oauth2Client := &oauth2client.Client{
				ID:             uuid.New(),
				Secret:         nil,
				RotatedSecrets: nil,
				RedirectURIs:   nil,
				GrantTypes:     nil,
				ResponseTypes:  nil,
				Scopes:         []string{"awesome"},
				Audience:       nil,
			}

			_, err = clientManager.InsertClient(context.Background(), oauth2Client)
			assert.NoError(t, err)

			sign := uuid.New()
			sesExtra := map[string]interface{}{
				"opState": "2135441",
			}

			ses := &fosite.Request{
				ID:                uuid.New(),
				Client:            oauth2Client,
				RequestedScope:    []string{"scope1"},
				GrantedScope:      []string{"scope1"},
				RequestedAudience: []string{"aud1"},
				GrantedAudience:   []string{"aud2"},
				Lang:              language.Tag{},
				Session: &fosite.DefaultSession{
					Extra: sesExtra,
				},
			}

			err = s.CreateAccessTokenSession(context.TODO(), sign, ses)
			assert.NoError(t, err)

			dbSes, err := s.GetAccessTokenSession(context.TODO(), sign, new(fosite.DefaultSession))
			assert.NoError(t, err)
			assert.Equal(t, ses, dbSes)
			assert.Equal(t, oauth2Client.ID, dbSes.GetClient().GetID())
			assert.Equal(t, sesExtra, dbSes.GetSession().(*fosite.DefaultSession).Extra)

			if testCase.useRevoke {
				err = s.RevokeAccessToken(context.TODO(), ses.ID)
				assert.NoError(t, err)
			} else {
				err = s.DeleteAccessTokenSession(context.TODO(), sign)
				assert.NoError(t, err)
			}

			resp, err := s.GetAccessTokenSession(context.TODO(), sign, ses.Session)
			assert.Nil(t, resp)
			assert.ErrorIs(t, err, dto.ErrDataNotFound)
		})
	}
}
