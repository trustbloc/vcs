#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running vc integration tests..."
PWD=`pwd`
TAGS="${TAGS:all}"
cd test/bdd
go test -count=1 -v -cover . -p 1 -timeout=20m -race
cd $PWD
