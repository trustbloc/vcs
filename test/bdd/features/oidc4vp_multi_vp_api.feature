#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@oidc4_multi_vp_rest
Feature: Using OIDC4VP REST API

  Background:
    Given Organization "test_org" has been authorized with client id "tenant-1" and secret "tenant-1-pwd"
    And   User creates wallet with 3 DID
    And   New verifiable credentials is created from table:
      | IssuerProfile                   | Organization | Credential                   | DIDIndex |
      | i_myprofile_cp_p384/v1.0        | test_org     | crude_product.json           | 0        |
      | i_myprofile_ud_es256k_jwt/v1.0  | test_org     | permanent_resident_card.json | 1        |
      | i_myprofile_ud_es384_sdjwt/v1.0 | test_org     | university_degree.json       | 2        |
    And User saves credentials into wallet

  Scenario: Initiate, check authorization response for jwt verifier
    Given OIDC4VP interaction initiated under "v_myprofile_multivp_jwt/v1.0" profile for organization "test_org"
    And Wallet verify authorization request and decode claims
    And Wallet looks for credential that match authorization multi VP
    And Wallet send authorization response
    And Verifier form organization "test_org" requests interactions claims