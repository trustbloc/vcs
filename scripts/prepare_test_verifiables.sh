#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

ROOT=`pwd`
OUTPUT_DIR=$ROOT/test/bdd/testdata/
INPUT_DIR=$ROOT/test/bdd/testdata/
CREDENTIALS=university_degree.json,permanent_resident_card.json,certified_mill_test_report.json,crude_product.json

echo "creating VCs for bddtests testdata"
cd $ROOT/.build
npm install axios
OutputDir=${OUTPUT_DIR} InputDir=${INPUT_DIR} Credentials=${CREDENTIALS} node ./prepare-test-verifiables.js
