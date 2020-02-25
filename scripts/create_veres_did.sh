#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

rm -rf $HOME/.dids/
cd .build
npm install did-cli
cd node_modules/did-cli
./did generate -r

echo "go to $HOME/.dids/keys and get did id and privateKeyBase58"
