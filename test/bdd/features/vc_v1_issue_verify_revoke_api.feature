#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_rest_v1
Feature: Using VC REST API

  @e2e_ldp_jwt_sdjwt_success
  Scenario Outline: Store, retrieve, verify and revoke credential using different kind of profiles (LDP, JWT, SD-JWT).
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And V1 New verifiable credential is issued from "<credential>" under "<issuerProfile>" profile
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And V1 verifiable credential is verified under "<verifierProfile>" profile

    Then  V1 verifiable credential is successfully revoked under "<issuerProfile>" profile
    Then we wait 3 seconds
    And   V1 revoked credential is unable to be verified under "<verifierProfile>" profile

    Examples:
      | issuerProfile                     | verifierProfile      | credential                      |
      | i_myprofile_cmtr_p256_ldp/v1.0    | v_myprofile_ldp/v1.0 | certified_mill_test_report.json |
      | i_myprofile_ud_es256k_jwt/v1.0    | v_myprofile_jwt/v1.0 | permanent_resident_card.json    |
      | i_myprofile_ud_es256k_sdjwt/v1.0  | v_myprofile_jwt/v1.0 | crude_product.json              |
      | i_myprofile_ud_di_ecdsa-2019/v1.0 | v_myprofile_ldp/v1.0 | crude_product.json              |

  @e2e_ldp_jwt_sdjwt_revoke_err
  Scenario Outline: Unsuccessful attempt to revoke credential from wrong issuer (LDP, JWT, SD-JWT).
    Given   Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And V1 New verifiable credential is issued from "<credential>" under "<issuerProfile>" profile
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And   V1 verifiable credential is verified under "<verifierProfile>" profile

    Then Profile "<wrongIssuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And V1 "<wrongIssuerProfile>" did unsuccessful attempt to revoke credential
    And   V1 verifiable credential is verified under "<verifierProfile>" profile

    Examples:
      | issuerProfile                    | wrongIssuerProfile              | verifierProfile      | credential                      |
      | i_myprofile_ud_P256k1/v1.0       | i_myprofile_ud_es256_jwt/v1.0   | v_myprofile_ldp/v1.0 | certified_mill_test_report.json |
      | i_myprofile_ud_es256k_jwt/v1.0   | i_myprofile_ud_es256_sdjwt/v1.0 | v_myprofile_jwt/v1.0 | permanent_resident_card.json    |
      | i_myprofile_ud_es256k_sdjwt/v1.0 | i_myprofile_ud_P256k1/v1.0      | v_myprofile_jwt/v1.0 | crude_product.json              |

  @e2e_ldp_jwt_sdjwt_verify_format_err
  Scenario Outline: Credential verification failed due to unsupported credential format by verifier (LDP, JWT, SD-JWT).
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And V1 New verifiable credential is issued from "<credential>" under "<issuerProfile>" profile
    And Profile "<wrongVerifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And   V1 verifiable credential with wrong format is unable to be verified under "<wrongVerifierProfile>" profile

    Examples:
      | issuerProfile                    | wrongVerifierProfile | credential                      |
      | i_myprofile_ud_P256k1/v1.0       | v_myprofile_jwt/v1.0 | certified_mill_test_report.json |
      | i_myprofile_ud_es256k_jwt/v1.0   | v_myprofile_ldp/v1.0 | permanent_resident_card.json    |
      | i_myprofile_ud_es256k_sdjwt/v1.0 | v_myprofile_ldp/v1.0 | crude_product.json              |
