#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@oidc4_multi_vp_rest
Feature: Using OIDC4VP REST API

  Background:
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   User creates wallet with 2 DID
    And   New verifiable credentials is created from table:
      | IssuerProfile               | Organization | Credential                      | VCFormat         | DIDIndex |
      | i_myprofile_cp_p384         | test_org     | crude_product.json              | ldp_vc           | 0        |
      | i_myprofile_ud_es384_sdjwt  | test_org     | university_degree.json          | jwt_vc_json-ld   | 1        |
    And User saves credentials into wallet

  Scenario: Initiate, check authorization response for jwt verifier
    Given OIDC4VP interaction initiated under "v_myprofile_multivp_jwt" profile for organization "test_org"
    And Wallet verify authorization request and decode claims
    And Wallet looks for credential that match authorization
    And Wallet send authorization response
    And Verifier form organization "test_org" requests interactions claims