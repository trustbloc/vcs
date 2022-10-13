#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@oidc4vp_rest
Feature: Using OIDC4VP REST API

  Background:
    Given Organization "test_org" has been authorized with client id "test_org" and secret "test-org-secret"
    And   User creates wallet
    And   New verifiable credentials is created from table:
      | IssuerProfile             | Organization | Credential                      | VCFormat |
      | i_myprofile_ud_P256k1     | test_org     | university_degree.json          | ldp_vc   |
      | i_myprofile_ud_p256       | test_org     | university_degree.json          | ldp_vc   |
      | i_myprofile_prc_P256k1    | test_org     | permanent_resident_card.json    | ldp_vc   |
      | i_myprofile_prc_p256      | test_org     | permanent_resident_card.json    | ldp_vc   |
      | i_myprofile_cp_p384       | test_org     | crude_product.json              | ldp_vc   |
      | i_myprofile_cp_p256       | test_org     | crude_product.json              | ldp_vc   |
      | i_myprofile_cmtr_p384     | test_org     | certified_mill_test_report.json | ldp_vc   |
      | i_myprofile_cmtr_p256     | test_org     | certified_mill_test_report.json | ldp_vc   |
      | i_myprofile_ud_es256_jwt  | test_org     | university_degree.json          | jwt_vc   |
      | i_myprofile_ud_es384_jwt  | test_org     | university_degree.json          | jwt_vc   |
      | i_myprofile_ud_es256k_jwt | test_org     | university_degree.json          | jwt_vc   |
    And User saves credentials into wallet

  @e2e
  Scenario: Initiate, check authorization response for ldp verifier
    Given OIDC4VP interaction initiated under "v_myprofile_ldp" profile for organization "test_org"
    And Wallet verify authorization request and decode claims
    And Wallet looks for credential that match authorization
    And Wallet send authorization response

  Scenario: Initiate, check authorization response for jwt verifier
    Given OIDC4VP interaction initiated under "v_myprofile_jwt" profile for organization "test_org"
    And Wallet verify authorization request and decode claims
    And Wallet looks for credential that match authorization
    And Wallet send authorization response