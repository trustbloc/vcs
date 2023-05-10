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
    And   User creates wallet with 2 DID
    And   New verifiable credentials is created from table:
      | IssuerProfile                   | Organization | Credential                      | VCFormat       | DIDIndex |
      | i_myprofile_ud_P256k1/v1.0      | test_org     | university_degree.json          | ldp_vc         | 0        |
      | i_myprofile_ud_p256/v1.0        | test_org     | university_degree.json          | ldp_vc         | 0        |
      | i_myprofile_cp_p384/v1.0        | test_org     | crude_product.json              | ldp_vc         | 0        |
      | i_myprofile_cmtr_p256/v1.0      | test_org     | certified_mill_test_report.json | ldp_vc         | 0        |
      | i_myprofile_ud_es256k_jwt/v1.0  | test_org     | university_degree.json          | jwt_vc_json-ld | 0        |
      | i_myprofile_ud_es256_sdjwt/v1.0 | test_org     | university_degree.json          | jwt_vc_json-ld | 0        |
      | i_myprofile_ud_es384_sdjwt/v1.0 | test_org     | university_degree.json          | jwt_vc_json-ld | 0        |
    And User saves credentials into wallet

  @e2e
  Scenario Outline: Initiate, check authorization response for ldp verifier with specific presentation definition ID and fields
    Given OIDC4VP interaction initiated under "v_myprofile_ldp/v1.0" profile for organization "test_org" with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Wallet verify authorization request and decode claims
    And Wallet looks for credential that match authorization
    And Wallet send authorization response
    And Verifier form organization "test_org" requests interactions claims
    Then we wait 2 seconds
    And Verifier form organization "test_org" requests deleted interactions claims
    Examples:
      | presentationDefinitionID                  | fields                                                       |
      | 32f54163-no-limit-disclosure-single-field | degree_type_id                                               |
      | 3c8b1d9a-limit-disclosure-optional-fields | unit_of_measure_barrel,api_gravity,category,supplier_address |
      | lp403pb9-schema-match                     | schema_id                                                    |

  Scenario: Initiate, check received claims expiry for ldp verifier
    Given OIDC4VP interaction initiated under "v_myprofile_ldp/v1.0" profile for organization "test_org" with presentation definition ID "32f54163-no-limit-disclosure-single-field" and fields "degree_type_id"
    And Wallet verify authorization request and decode claims
    And Wallet looks for credential that match authorization
    And Wallet send authorization response
    And Verifier form organization "test_org" waits for interaction succeeded event
    Then we wait 15 seconds
    And Verifier form organization "test_org" requests expired interactions claims

  Scenario: Initiate, check authorization response for jwt verifier
    Given OIDC4VP interaction initiated under "v_myprofile_jwt/v1.0" profile for organization "test_org"
    And Wallet verify authorization request and decode claims
    And Wallet looks for credential that match authorization
    And Wallet send authorization response
    And Verifier form organization "test_org" requests interactions claims
    Then we wait 2 seconds
    And Verifier form organization "test_org" requests deleted interactions claims