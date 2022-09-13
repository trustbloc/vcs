#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_rest
Feature: Using VC REST API

  @e2e
  Scenario Outline: Store, retrieve, verify credential and presentation using different kind of profiles
    Given V1 Profile "<profile>" for organization "<organization>" is created with signatureHolder "<signatureHolder>", didMethod "<didMethod>", signatureType "<signatureType>" and keyType "<keyType>"
    And   V1 We can retrieve profile "<profile>" with DID "<didMethod>" and signatureType "<signatureType>"
    And   V1 New verifiable credential is created from "<credential>" under "<profile>" profile

    Examples:
      | profile                        | organization | credential                      | signatureHolder | didMethod | signatureType        | keyType      |
      | myprofile_ud_local_ed25519_jws | test_org     | university_degree.json          | JWS             | orb       | Ed25519Signature2018 | Ed25519      |
      | myprofile_ud_local_p256_pv     | test_org     | university_degree.json          | ProofValue      | orb       | JsonWebSignature2020 | ECDSAP256DER |
      | myprofile_prc_unireg_ed25519   | test_org     | permanent_resident_card.json    | JWS             | orb       | JsonWebSignature2020 | Ed25519      |
      | myprofile_prc_unireg_p256      | test_org     | permanent_resident_card.json    | JWS             | orb       | JsonWebSignature2020 | ECDSAP256DER |
      | myprofile_cp_unireg_ed25519    | test_org     | crude_product.json              | JWS             | orb       | JsonWebSignature2020 | Ed25519      |
      | myprofile_cp_unireg_p256       | test_org     | crude_product.json              | JWS             | orb       | JsonWebSignature2020 | ECDSAP256DER |
      | myprofile_cmtr_unireg_ed25519  | test_org     | certified_mill_test_report.json | JWS             | orb       | JsonWebSignature2020 | Ed25519      |
      | myprofile_cmtr_unireg_p256     | test_org     | certified_mill_test_report.json | JWS             | orb       | JsonWebSignature2020 | ECDSAP256DER |

