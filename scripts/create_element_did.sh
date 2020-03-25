#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

cd .build
npm install @transmute/element-lib
npm install axios
ElementAPIURL=${REQUEST_URL} node ./create-element-did.js
