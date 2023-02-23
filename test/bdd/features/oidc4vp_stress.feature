#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@oidc4vp_stress
Feature: Using OIDC4VP REST API

  Background:
    When "ACCESS_TOKEN_URL" Organization "ORG_ID" has been authorized with client id "CLIENT_ID" and secret "SECRET"
    And   User creates wallet
    And   New verifiable credentials is created from table:
      | IssuerProfile               | Organization | Credential                      | VCFormat        |
      | i_myprofile_ud_P256k1       | test_org     | university_degree.json          | ldp_vc          |
      | i_myprofile_ud_p256         | test_org     | university_degree.json          | ldp_vc          |
      | i_myprofile_prc_P256k1      | test_org     | permanent_resident_card.json    | ldp_vc          |
      | i_myprofile_prc_p256        | test_org     | permanent_resident_card.json    | ldp_vc          |
      | i_myprofile_cp_p384         | test_org     | crude_product.json              | ldp_vc          |
      | i_myprofile_cp_p256         | test_org     | crude_product.json              | ldp_vc          |
      | i_myprofile_cmtr_p384       | test_org     | certified_mill_test_report.json | ldp_vc          |
      | i_myprofile_cmtr_p256       | test_org     | certified_mill_test_report.json | ldp_vc          |
      | i_myprofile_ud_es256_jwt    | test_org     | university_degree.json          | jwt_vc_json-ld  |
      | i_myprofile_ud_es384_jwt    | test_org     | university_degree.json          | jwt_vc_json-ld  |
      | i_myprofile_ud_es256k_jwt   | test_org     | university_degree.json          | jwt_vc_json-ld  |
      | i_myprofile_ud_es256_sdjwt  | test_org     | university_degree.json          | jwt_vc_json-ld  |
      | i_myprofile_ud_es384_sdjwt  | test_org     | university_degree.json          | jwt_vc_json-ld  |
      | i_myprofile_ud_es256k_sdjwt | test_org     | university_degree.json          | jwt_vc_json-ld  |
    And User saves credentials into wallet

  @e2e

  Scenario: Stress test method
    And  "USER_NUMS" users execute oidc4vp flow with init "INIT_INTERACTION_URL" url, with retrieve "RETRIEVE_CLAIMS_URL" url, for verify profile "VERIFY_PROFILE_ID" and org id "ORG_ID" using "CONCURRENT_REQ" concurrent requests