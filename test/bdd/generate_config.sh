#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


# TODO: verify parameters fit this bdd test
../../build/did-method-cli/cli create-config --sidetree-url https://localhost:48326/sidetree/0.0.1 --tls-cacerts ../../test/bdd/fixtures/keys/tls/ec-cacert.pem --sidetree-write-token rw_token --config-file ./fixtures/wellknown/config.json --output-directory ./fixtures/wellknown/jws 2>&1
rm -rf ./fixtures/wellknown/jws/stakeholder.one
mv ./fixtures/wellknown/jws/stakeholder.one:8088 ./fixtures/wellknown/jws/stakeholder.one
