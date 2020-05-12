#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running interop integration tests..."
PWD=`pwd`
cd test/bdd
TAGS=interop go test -count=1 -v -cover . -p 1 -timeout=20m -race
cd $PWD