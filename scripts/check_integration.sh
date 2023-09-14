#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e


TAGS=${TAGS:-all}

PWD=`pwd`
cd test/bdd

echo "Running vcs integration tests with tag=$TAGS"


go test -count=1 -v -cover . -p 1 -timeout=40m $TAGS

cd $PWD
