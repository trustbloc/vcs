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
INPUT_CREDENTIAL=$ROOT/test/bdd/testdata/university_degree_credential.json

echo "creating VCs for bddtests testdata"
cd $ROOT/.build
npm install axios
OutputDir=${OUTPUT_DIR} CredentialPath=${INPUT_CREDENTIAL} node ./prepare-test-verifiables.js
