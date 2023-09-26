#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@oidc4vp_stress
Feature: Using OIDC4VP REST API

  Background:
    When User creates wallet with 1 DID
    And   With AccessTokenUrlEnv "ACCESS_TOKEN_URL", new verifiable credentials is created from table:
      | IssuerProfile                    | UserName                  | Password                        |Credential                       | VCFormat       |
      | i_myprofile_ud_P256k1/v1.0       | profile-user-issuer-1     | profile-user-issuer-1-pwd       | university_degree.json          | ldp_vc         |
      | i_myprofile_ud_p256/v1.0         | profile-user-issuer-1     | profile-user-issuer-1-pwd       | university_degree.json          | ldp_vc         |
      | i_myprofile_prc_P256k1/v1.0      | profile-user-issuer-1     | profile-user-issuer-1-pwd       | permanent_resident_card.json    | ldp_vc         |
      | i_myprofile_prc_p256/v1.0        | profile-user-issuer-1     | profile-user-issuer-1-pwd       | permanent_resident_card.json    | ldp_vc         |
      | i_myprofile_cp_p384/v1.0         | profile-user-issuer-1     | profile-user-issuer-1-pwd       | crude_product.json              | ldp_vc         |
      | i_myprofile_cp_p256/v1.0         | profile-user-issuer-1     | profile-user-issuer-1-pwd       | crude_product.json              | ldp_vc         |
      | i_myprofile_cmtr_p384/v1.0       | profile-user-issuer-1     | profile-user-issuer-1-pwd       | certified_mill_test_report.json | ldp_vc         |
      | i_myprofile_cmtr_p256_ldp/v1.0   | profile-user-issuer-1     | profile-user-issuer-1-pwd       | certified_mill_test_report.json | ldp_vc         |
      | i_myprofile_ud_es256_jwt/v1.0    | profile-user-issuer-1     | profile-user-issuer-1-pwd       | university_degree.json          | jwt_vc_json-ld |
      | i_myprofile_ud_es384_jwt/v1.0    | profile-user-issuer-1     | profile-user-issuer-1-pwd       | university_degree.json          | jwt_vc_json-ld |
      | i_myprofile_ud_es256k_jwt/v1.0   | profile-user-issuer-1     | profile-user-issuer-1-pwd       | university_degree.json          | jwt_vc_json-ld |
      | i_myprofile_ud_es256_sdjwt/v1.0  | profile-user-issuer-1     | profile-user-issuer-1-pwd       | university_degree.json          | jwt_vc_json-ld |
      | i_myprofile_ud_es384_sdjwt/v1.0  | profile-user-issuer-1     | profile-user-issuer-1-pwd       | university_degree.json          | jwt_vc_json-ld |
      | i_myprofile_ud_es256k_sdjwt/v1.0 | profile-user-issuer-1     | profile-user-issuer-1-pwd       | university_degree.json          | jwt_vc_json-ld |
    And User saves credentials into wallet
    And Profile "v_myprofile_jwt/v1.0" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

  @e2e

  Scenario: Stress test method
    And  "USER_NUMS" users execute oidc4vp flow with init "INIT_INTERACTION_URL" url, with retrieve "RETRIEVE_CLAIMS_URL" url, for verify profile "VERIFY_PROFILE_ID" using "CONCURRENT_REQ" concurrent requests