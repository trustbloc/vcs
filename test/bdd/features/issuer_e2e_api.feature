#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@issuer_rest
Feature: Issuer VC REST API

  @issueCred_api
  Scenario: Issue Credential API
    Given "University" has a DID with the public key generated from Issuer Service - Generate Keypair API
    And   "University" creates an Issuer Service profile "university-profile" with the DID
    Then  "University" application service verifies the credential created by Issuer Service - Issue Credential API with it's DID

  @composeAndIssueCred_api
  Scenario: Compose and Issue Credential API
    Given "University" has a DID with the public key generated from Issuer Service - Generate Keypair API
    And   "University" creates an Issuer Service profile "university-profile" with the DID
    Then  "University" application service verifies the credential created by Issuer Service - Compose And Issue Credential API with it's DID