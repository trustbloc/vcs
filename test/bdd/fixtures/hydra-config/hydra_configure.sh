#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Creating OAuth2 clients..."

hydra clients create \
    --endpoint https://oidc-provider.example.com:4445 \
    --id test_org \
    --secret test-org-secret \
    --grant-types client_credentials \
    --response-types token,code \
    --scope org_admin \
    --skip-tls-verify

# issuer's oauth2 client account on third-party OIDC provider
hydra clients create \
    --endpoint https://oidc-provider.example.com:4445 \
    --id bank_issuer \
    --secret bank-issuer-secret \
    --grant-types authorization_code \
    --response-types code \
    --scope openid,profile \
    --callbacks https://localhost:4455/oidc/redirect \
    --skip-tls-verify

echo "Finished creating OAuth2 clients"
