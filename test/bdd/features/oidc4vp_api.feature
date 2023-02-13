#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@oidc4vp_rest
Feature: Using OIDC4VP REST API

  Background:
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   User creates wallet
    And   New verifiable credentials is created from table:
      | IssuerProfile               | Organization | Credential                      | VCFormat      |
      | i_myprofile_ud_P256k1       | test_org     | university_degree.json          | ldp_vc        |
      | i_myprofile_ud_p256         | test_org     | university_degree.json          | ldp_vc        |
      | i_myprofile_cp_p384         | test_org     | crude_product.json              | ldp_vc        |
      | i_myprofile_cmtr_p256       | test_org     | certified_mill_test_report.json | ldp_vc        |
      | i_myprofile_ud_es256k_jwt   | test_org     | university_degree.json          | jwt_vc_json   |
      | i_myprofile_ud_es256_sdjwt  | test_org     | university_degree.json          | jwt_vc_json   |
      | i_myprofile_ud_es384_sdjwt  | test_org     | university_degree.json          | jwt_vc_json   |
    And User saves credentials into wallet

  @e2e
  Scenario: Initiate, check authorization response for ldp verifier
    Given OIDC4VP interaction initiated under "v_myprofile_ldp" profile for organization "test_org"
    And Wallet verify authorization request and decode claims
    And Wallet looks for credential that match authorization
    And Wallet send authorization response
    And Verifier form organization "test_org" requests interactions claims

  Scenario: Initiate, check authorization response for jwt verifier
    Given OIDC4VP interaction initiated under "v_myprofile_jwt" profile for organization "test_org"
    And Wallet verify authorization request and decode claims
    And Wallet looks for credential that match authorization
    And Wallet send authorization response
    And Verifier form organization "test_org" requests interactions claims