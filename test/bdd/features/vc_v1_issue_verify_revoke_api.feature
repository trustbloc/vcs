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
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And V1 New verifiable credential is issued from "<credential>" under "<issuerProfile>" profile
    And issued credential history is updated
    # Login with username & password that has role "activator"
    Then Profile "<issuerProfile>" issuer has been authorized with username "profile-user-activator-1" and password "profile-user-activator-1-pwd"
    # Attempt to revoke credential with "activator" role
    And V1 "<issuerProfile>" did unsuccessful attempt to revoke credential: "client is not allowed to perform the action"
    #   Verify credential is still active
    And V1 verifiable credential is verified under "<verifierProfile>" profile
    # Login with username & password that has role "revoker"
    Then Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
#    Revoke credential with "revoker" role
    And  V1 verifiable credential is successfully revoked under "<issuerProfile>" profile
    # Attempt to activate credential with "revoker" role
    And V1 "<issuerProfile>" did unsuccessful attempt to activate credential: "client is not allowed to perform the action"
    # Verify that credential is still revoked
    Then we wait 3 seconds
    And V1 revoked credential is unable to be verified under "<verifierProfile>" profile
    # Login with username & password that has role "activator"
    Then Profile "<issuerProfile>" issuer has been authorized with username "profile-user-activator-1" and password "profile-user-activator-1-pwd"
    # Activate credential with "activator" role
    And  V1 verifiable credential is successfully activated under "<issuerProfile>" profile
    #   Verify credential is active
    Then we wait 3 seconds
    And V1 verifiable credential is verified under "<verifierProfile>" profile

    Examples:
      | issuerProfile                     | verifierProfile                | credential                      |
      | i_myprofile_cmtr_p256_ldp/v1.0    | v_myprofile_ldp/v1.0           | certified_mill_test_report.json |
      | i_myprofile_ud_es256k_jwt/v1.0    | v_myprofile_jwt/v1.0           | permanent_resident_card.json    |
      | i_myprofile_ud_es256k_sdjwt/v1.0  | v_myprofile_jwt_no_strict/v1.0 | crude_product.json              |
      | i_myprofile_ud_di_ecdsa-2019/v1.0 | v_myprofile_ldp/v1.0           | crude_product.json              |
      | i_myprofile_cmtr_p256_ldp_v2/v1.0 | v_myprofile_ldp/v1.0           | crude_product_vcdm2.json        |

  @e2e_bitstring_status_list_suspend_and_revoke_success
  Scenario Outline: Store, retrieve, verify, suspend, unsuspend, and revoke credential.
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And V1 New verifiable credential is issued from "<credential>" under "<issuerProfile>" profile
    And issued credential history is updated

    # ********** Attempt to suspend credential with "activator" role **********
    # Login with username & password that has role "activator"
    Then Profile "<issuerProfile>" issuer has been authorized with username "profile-user-activator-1" and password "profile-user-activator-1-pwd"
    # Attempt to suspend credential with "activator" role
    And V1 "<issuerProfile>" did unsuccessful attempt to suspend credential: "client is not allowed to perform the action"
    # Verify credential is still active
    And V1 verifiable credential is verified under "<verifierProfile>" profile
    # Login with username & password that has role "revoker"
    Then Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    # Suspend credential with "revoker" role
    And  V1 verifiable credential is successfully suspended under "<issuerProfile>" profile
    # Verify that credential is suspended
    Then we wait 3 seconds
    And V1 suspended credential is unable to be verified under "<verifierProfile>" profile

    # ********** Attempt to un-suspend credential with "activator" role **********
    # Login with username & password that has role "activator"
    Then Profile "<issuerProfile>" issuer has been authorized with username "profile-user-activator-1" and password "profile-user-activator-1-pwd"
    # Activate credential with "activator" role
    And V1 verifiable credential is successfully unsuspended under "<issuerProfile>" profile
    #   Verify credential is active
    Then we wait 3 seconds
    And V1 verifiable credential is verified under "<verifierProfile>" profile

    # ********** Attempt to revoke credential with "activator" role **********
    # Attempt to revoke credential with "activator" role
    And V1 "<issuerProfile>" did unsuccessful attempt to revoke credential: "client is not allowed to perform the action"
    #   Verify credential is still active
    And V1 verifiable credential is verified under "<verifierProfile>" profile
    # Login with username & password that has role "revoker"
    Then Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
#    Revoke credential with "revoker" role
    And  V1 verifiable credential is successfully revoked under "<issuerProfile>" profile
    # Verify that credential is revoked
    Then we wait 3 seconds
    And V1 revoked credential is unable to be verified under "<verifierProfile>" profile

    Examples:
      | issuerProfile                     | verifierProfile      | credential               |
      | i_myprofile_cmtr_p256_ldp_v2/v1.0 | v_myprofile_ldp/v1.0 | crude_product_vcdm2.json |

  @e2e_ldp_jwt_sdjwt_revoke_err
  Scenario Outline: Unsuccessful attempt to revoke credential from wrong issuer (LDP, JWT, SD-JWT).
    Given   Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And V1 New verifiable credential is issued from "<credential>" under "<issuerProfile>" profile
    And issued credential history is updated
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And   V1 verifiable credential is verified under "<verifierProfile>" profile

    Then Profile "<wrongIssuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And V1 "<wrongIssuerProfile>" did unsuccessful attempt to revoke credential: "not found"
    And   V1 verifiable credential is verified under "<verifierProfile>" profile

    Examples:
      | issuerProfile                    | wrongIssuerProfile              | verifierProfile                | credential                      |
      | i_myprofile_ud_P256k1/v1.0       | i_myprofile_ud_es256_jwt/v1.0   | v_myprofile_ldp/v1.0           | certified_mill_test_report.json |
      | i_myprofile_ud_es256k_jwt/v1.0   | i_myprofile_ud_es256_sdjwt/v1.0 | v_myprofile_jwt/v1.0           | permanent_resident_card.json    |
      | i_myprofile_ud_es256k_sdjwt/v1.0 | i_myprofile_ud_P256k1/v1.0      | v_myprofile_jwt_no_strict/v1.0 | crude_product.json              |

  @e2e_ldp_jwt_sdjwt_verify_format_err
  Scenario Outline: Credential verification failed due to unsupported credential format by verifier (LDP, JWT, SD-JWT).
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And V1 New verifiable credential is issued from "<credential>" under "<issuerProfile>" profile
    And issued credential history is updated
    And Profile "<wrongVerifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And   V1 verifiable credential is unable to be verified under "<wrongVerifierProfile>" profile error: "invalid format"

    Examples:
      | issuerProfile                    | wrongVerifierProfile | credential                      |
      | i_myprofile_ud_P256k1/v1.0       | v_myprofile_jwt/v1.0 | certified_mill_test_report.json |
      | i_myprofile_ud_es256k_jwt/v1.0   | v_myprofile_ldp/v1.0 | permanent_resident_card.json    |
      | i_myprofile_ud_es256k_sdjwt/v1.0 | v_myprofile_ldp/v1.0 | crude_product.json              |
