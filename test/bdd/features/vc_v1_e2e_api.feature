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
    Given V1 Issuer profile "<issuerProfile>" for organization "<organization>" is created with signatureHolder "<signatureHolder>", didMethod "<didMethod>", signatureType "<signatureType>" and keyType "<keyType>"
    And   V1 We can retrieve issuer profile "<issuerProfile>" with DID "<didMethod>" and signatureType "<signatureType>" for organization "<organization>"
    Given V1 Verifier profile "<verifierProfile>" for organization "<organization>" is created"
    And   V1 We can retrieve verifier profile "<verifierProfile>" for organization "<organization>"
    And   V1 New verifiable credential is created from "<credential>" under "<issuerProfile>" profile for organization "<organization>"
    And   V1 verifiable credential is verified under "<verifierProfile>" profile for organization "<organization>"

    Examples:
      | issuerProfile                    | verifierProfile                  | organization | credential                      | signatureHolder | didMethod | signatureType        | keyType      |
      | i_myprofile_ud_local_ed25519_jws | v_myprofile_ud_local_ed25519_jws | test_org     | university_degree.json          | JWS             | orb       | Ed25519Signature2018 | Ed25519      |
      | i_myprofile_ud_local_p256_pv     | v_myprofile_ud_local_p256_pv     | test_org     | university_degree.json          | ProofValue      | orb       | JsonWebSignature2020 | ECDSAP256DER |
      | i_myprofile_prc_unireg_ed25519   | v_myprofile_prc_unireg_ed25519   | test_org     | permanent_resident_card.json    | JWS             | orb       | JsonWebSignature2020 | Ed25519      |
      | i_myprofile_prc_unireg_p256      | v_myprofile_prc_unireg_p256      | test_org     | permanent_resident_card.json    | JWS             | orb       | JsonWebSignature2020 | ECDSAP256DER |
      | i_myprofile_cp_unireg_ed25519    | v_myprofile_cp_unireg_ed25519    | test_org     | crude_product.json              | JWS             | orb       | JsonWebSignature2020 | Ed25519      |
      | i_myprofile_cp_unireg_p256       | v_myprofile_cp_unireg_p256       | test_org     | crude_product.json              | JWS             | orb       | JsonWebSignature2020 | ECDSAP256DER |
      | i_myprofile_cmtr_unireg_ed25519  | v_myprofile_cmtr_unireg_ed25519  | test_org     | certified_mill_test_report.json | JWS             | orb       | JsonWebSignature2020 | Ed25519      |
      | i_myprofile_cmtr_unireg_p256     | v_myprofile_cmtr_unireg_p256     | test_org     | certified_mill_test_report.json | JWS             | orb       | JsonWebSignature2020 | ECDSAP256DER |

