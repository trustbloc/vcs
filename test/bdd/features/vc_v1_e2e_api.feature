#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_rest_v1
Feature: Using VC REST API
  Background:
    Given Organization "test_org" has been authorized with client id "test_org" and secret "test-org-secret"

  @e2e
  Scenario Outline: Store, retrieve, verify credential and presentation using different kind of profiles
    Given   V1 New verifiable credential is created from "<credential>" under "<issuerProfile>" profile for organization "<organization>" with signature representation "<signatureHolder>"
    And   V1 verifiable credential is verified under "<verifierProfile>" profile for organization "<organization>"

    Examples:
      | issuerProfile             | verifierProfile  | organization | credential                      | signatureHolder |
      | i_myprofile_ud_P256k1     | v_myprofile      | test_org     | university_degree.json          | JWS             |
      | i_myprofile_ud_p256       | v_myprofile      | test_org     | university_degree.json          | JWS             |
      | i_myprofile_prc_P256k1    | v_myprofile      | test_org     | permanent_resident_card.json    | JWS             |
      | i_myprofile_prc_p256      | v_myprofile      | test_org     | permanent_resident_card.json    | JWS             |
      | i_myprofile_cp_p384       | v_myprofile      | test_org     | crude_product.json              | JWS             |
      | i_myprofile_cp_p256       | v_myprofile      | test_org     | crude_product.json              | JWS             |
      | i_myprofile_cmtr_p384     | v_myprofile      | test_org     | certified_mill_test_report.json | JWS             |
      | i_myprofile_cmtr_p256     | v_myprofile      | test_org     | certified_mill_test_report.json | JWS             |

