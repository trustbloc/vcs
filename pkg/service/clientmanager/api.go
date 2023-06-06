/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientmanager

import (
	"context"

	"github.com/trustbloc/vcs/pkg/oauth2client"
)

type ServiceInterface interface {
	CreateClient(ctx context.Context, req *ClientMetadata) (*oauth2client.Client, error)
}
