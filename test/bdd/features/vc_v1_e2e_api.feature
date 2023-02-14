#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_rest_v1
Feature: Using VC REST API

  Background:
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"

  @e2e
  Scenario Outline: Store, retrieve, verify credential and presentation using different kind of profiles
    Given   V1 New verifiable credential is created from "<credential>" in "<vcFormat>" format under "<issuerProfile>" profile for organization "<organization>" with signature representation "<signatureHolder>"
    And   V1 verifiable credential is verified under "<verifierProfile>" profile for organization "<organization>"
    Then   V1 verifiable credential is revoked under "<issuerProfile>" profile for organization "<organization>"
    And   V1 verifiable credential is unable to be verified under "<verifierProfile>" profile for organization "<organization>"

    Examples:
      | issuerProfile               | verifierProfile | organization | credential                      | vcFormat      | signatureHolder |
      | i_myprofile_ud_P256k1       | v_myprofile_ldp | test_org     | university_degree.json          | ldp_vc        | JWS             |
      | i_myprofile_ud_p256         | v_myprofile_ldp | test_org     | university_degree.json          | ldp_vc        | JWS             |
      | i_myprofile_prc_P256k1      | v_myprofile_ldp | test_org     | permanent_resident_card.json    | ldp_vc        | JWS             |
      | i_myprofile_prc_p256        | v_myprofile_ldp | test_org     | permanent_resident_card.json    | ldp_vc        | JWS             |
      | i_myprofile_cp_p384         | v_myprofile_ldp | test_org     | crude_product.json              | ldp_vc        | JWS             |
      | i_myprofile_cp_p256         | v_myprofile_ldp | test_org     | crude_product.json              | ldp_vc        | JWS             |
      | i_myprofile_cmtr_p384       | v_myprofile_ldp | test_org     | certified_mill_test_report.json | ldp_vc        | JWS             |
      | i_myprofile_cmtr_p256       | v_myprofile_ldp | test_org     | certified_mill_test_report.json | ldp_vc        | JWS             |
      | i_myprofile_ud_es256_jwt    | v_myprofile_jwt | test_org     | university_degree.json          | jwt_vc_json   | JWS             |
      | i_myprofile_ud_es384_jwt    | v_myprofile_jwt | test_org     | university_degree.json          | jwt_vc_json   | JWS             |
      | i_myprofile_ud_es256k_jwt   | v_myprofile_jwt | test_org     | university_degree.json          | jwt_vc_json   | JWS             |
      | i_myprofile_ud_es256_sdjwt  | v_myprofile_jwt | test_org     | university_degree.json          | jwt_vc_json   | JWS             |
      | i_myprofile_ud_es384_sdjwt  | v_myprofile_jwt | test_org     | university_degree.json          | jwt_vc_json   | JWS             |
      | i_myprofile_ud_es256k_sdjwt | v_myprofile_jwt | test_org     | university_degree.json          | jwt_vc_json   | JWS             |

