#
# Copyright Avast Software. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@oidc4vc_rest
Feature: OIDC4VC REST API

  @oidc4vc_rest_auth_flow
  Scenario Outline: OIDC credential issuance and verification Auth flow
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And  User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using authorization code flow with client registration method "<clientRegistrationMethod>"
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile                     | credentialType             | clientRegistrationMethod | credentialTemplate               | verifierProfile      | presentationDefinitionID                     | fields                                                       |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0                  | UniversityDegreeCredential | dynamic                  | universityDegreeTemplateID       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                               |
#      SDJWT issuer, JWT verifier, limit disclosure and optional fields in PD query.
      | bank_issuer/v1.0                  | CrudeProductCredential     | discoverable             | crudeProductCredentialTemplateID | v_myprofile_jwt/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields    | unit_of_measure_barrel,api_gravity,category,supplier_address |
#     JWT issuer, JWT verifier, no limit disclosure and optional fields in PD query.
      | i_myprofile_ud_es256k_jwt/v1.0    | PermanentResidentCard      | pre-registered           | permanentResidentCardTemplateID  | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,registration_city,commuter_classification    |
#     LDP Data Integrity issuer, LDP verifier, no limit disclosure and schema match in PD query.
      | i_myprofile_ud_di_ecdsa-2019/v1.0 | PermanentResidentCard      | pre-registered           | permanentResidentCardTemplateID  | v_myprofile_ldp/v1.0 | 062759b1-no-limit-disclosure-optional-fields | lpr_category_id,registration_city,commuter_classification    |
#     LDP issuer, LDP verifier, no limit disclosure and schema match in PD query.
      | i_myprofile_cmtr_p256_ldp/v1.0    | CrudeProductCredential     | pre-registered           | crudeProductCredentialTemplateID | v_myprofile_ldp/v1.0 | lp403pb9-schema-match                        | schema_id                                                    |

  @oidc4vc_rest_auth_flow_credential_conf_id
  Scenario Outline: OIDC credential issuance and verification Auth flow using credential configuration ID to request specific credential type
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And  User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using authorization code flow with credential configuration ID "<credentialConfigurationID>"
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile    | credentialType             | credentialConfigurationID            | clientRegistrationMethod | credentialTemplate         | verifierProfile      | presentationDefinitionID                  | fields         |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0 | UniversityDegreeCredential | UniversityDegreeCredentialIdentifier | dynamic                  | universityDegreeTemplateID | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id |

  @oidc4vc_rest_auth_flow_scope_based
  Scenario Outline: OIDC credential issuance and verification Auth flow using scopes to request specific credential type
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And  User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using authorization code flow with scopes "<scopes>"
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile    | credentialType             | scopes                         | clientRegistrationMethod | credentialTemplate         | verifierProfile      | presentationDefinitionID                  | fields         |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0 | UniversityDegreeCredential | UniversityDegreeCredential_001 | dynamic                  | universityDegreeTemplateID | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id |

  @oidc4vc_rest_pre_auth_flow
  Scenario Outline: OIDC credential issuance and verification Pre Auth flow
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And proofType is "<proofType>"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile                  | credentialType             | credentialTemplate               | verifierProfile      | presentationDefinitionID                     | fields                                                       | proofType |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0               | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                               | jwt       |
      | bank_issuer/v1.0               | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                               | ldp_vc    |
      | bank_issuer/v1.0               | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                               | cwt       |
      | acme_issuer/v1.0               | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                               | jwt       |
#      SDJWT issuer, JWT verifier, limit disclosure and optional fields in PD query.
      | bank_issuer/v1.0               | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_jwt/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields    | unit_of_measure_barrel,api_gravity,category,supplier_address | jwt       |
      | bank_issuer_sdjwt_v5/v1.0      | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_jwt/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields    | unit_of_measure_barrel,api_gravity,category,supplier_address | jwt       |
#     JWT issuer, JWT verifier, no limit disclosure and optional fields in PD query.
      | i_myprofile_ud_es256k_jwt/v1.0 | PermanentResidentCard      | permanentResidentCardTemplateID  | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,commuter_classification,registration_city    | jwt       |
#     LDP issuer, LDP verifier, no limit disclosure and schema match in PD query.
      | i_myprofile_cmtr_p256_ldp/v1.0 | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_ldp/v1.0 | lp403pb9-schema-match                        | schema_id                                                    | jwt       |

  @oidc4vc_rest_pre_auth_flow_trustlist_success
  Scenario Outline: OIDC credential issuance and verification Pre Auth flow with trustlist (Success)
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims
    Examples:
      | issuerProfile             | credentialType             | credentialTemplate               | verifierProfile                | presentationDefinitionID                  | fields                                                       |
      | bank_issuer_sdjwt_v5/v1.0 | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_jwt_whitelist/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields | unit_of_measure_barrel,api_gravity,category,supplier_address |
      | bank_issuer/v1.0          | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt_whitelist/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id                                               |

  @oidc4vc_rest_auth_flow_additional_scope
  Scenario Outline: OIDC credential issuance and verification Auth flow including additional scope
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And  User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using authorization code flow with client registration method "<clientRegistrationMethod>"
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>" and custom scopes "<customScopes>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims with additional claims associated with custom scopes "<customScopes>"
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile    | credentialType             | clientRegistrationMethod | credentialTemplate         | verifierProfile      | presentationDefinitionID                  | fields         | customScopes              |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0 | UniversityDegreeCredential | dynamic                  | universityDegreeTemplateID | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | timedetails,walletdetails |

# Error cases

  @oidc4vc_rest_pre_auth_flow_trustlist_fail
  Scenario Outline: OIDC credential issuance and verification Pre Auth flow with trustlist (Fail)
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>" and receives "is not a member of trustlist" error
    Examples:
      | issuerProfile                  | credentialType             | credentialTemplate              | verifierProfile                | presentationDefinitionID                     | fields                                                    |
      | bank_issuer_sdjwt_v5/v1.0      | UniversityDegreeCredential | universityDegreeTemplateID      | v_myprofile_jwt_whitelist/v1.0 | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                            |
      | i_myprofile_ud_es256k_jwt/v1.0 | PermanentResidentCard      | permanentResidentCardTemplateID | v_myprofile_jwt_whitelist/v1.0 | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,registration_city,commuter_classification |

  @oidc4vc_rest_pre_auth_flow_invalid_claims
  Scenario: OIDC credential issuance and verification Pre Auth flow (Invalid Claims)
    Given Profile "bank_issuer/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "UniversityDegreeCredential" with templateID "universityDegreeTemplateID"
    Then User interacts with Wallet to initiate credential issuance using pre authorization code flow with invalid claims

  @oidc4vc_rest_pre_auth_schema_validation_error
  Scenario: OIDC credential issuance and verification Pre Auth flow (Claims JSON schema validation error)
    Given Profile "bank_issuer/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    Then User interacts with Wallet to initiate credential issuance using pre authorization code flow with invalid claims schema

  @oidc4vc_rest_auth_schema_validation_error
  Scenario: OIDC credential issuance and verification Auth flow (Claims JSON schema validation error)
    Given Profile "bank_issuer/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    Then User interacts with Wallet to initiate credential issuance using authorization code flow with invalid claims schema

  Scenario: OIDC credential issuance and verification Pre Auth flow (Invalid Field in Presentation Definition)
    Given Profile "i_myprofile_ud_es256k_jwt/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "CrudeProductCredential" with templateID "crudeProductCredentialTemplateID"
    And Profile "v_myprofile_jwt/v1.0" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then credential is issued
    And User interacts with Verifier and initiate OIDC4VP interaction under "v_myprofile_jwt/v1.0" profile with presentation definition ID "32f54163-no-limit-disclosure-optional-fields" and fields "lpr_category_id,commuter_classification,invalidfield" and receives "field invalidfield not found" error

  Scenario: OIDC credential issuance and verification Auth flow (Malicious attacker stealing auth code & calling token endpoint with it)
    Given Profile "bank_issuer/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "UniversityDegreeCredential" with templateID "universityDegreeTemplateID"
    Then Malicious attacker stealing auth code from User and using "malicious_attacker_id" ClientID makes /token request and receives "invalid_client" error

  Scenario: OIDC credential issuance and verification Auth flow (Malicious attacker changed signingKeyID & calling credential endpoint with it)
    Given Profile "bank_issuer/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "UniversityDegreeCredential" with templateID "universityDegreeTemplateID"
    Then Malicious attacker changed JWT kid header and makes /credential request and receives "invalid_or_missing_proof" error

  Scenario: OIDC credential issuance and verification Auth flow (Malicious attacker changed JWT signature value & calling credential endpoint with it)
    Given Profile "bank_issuer/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "UniversityDegreeCredential" with templateID "universityDegreeTemplateID"
    Then Malicious attacker changed signature value and makes /credential request and receives "invalid_or_missing_proof" error

  Scenario: OIDC credential issuance and verification Auth flow (Malicious attacker changed nonce & calling credential endpoint with it)
    Given Profile "bank_issuer/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "UniversityDegreeCredential" with templateID "universityDegreeTemplateID"
    Then Malicious attacker changed nonce value and makes /credential request and receives "invalid_or_missing_proof" error

  Scenario: OIDC credential issuance and verification Pre Auth flow (issuer has pre-authorized_grant_anonymous_access_supported disabled)
    Given Profile "i_disabled_preauth_without_client_id/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "VerifiedEmployee" with templateID "templateID"
    Then User interacts with Wallet to initiate credential issuance using pre authorization code flow and receives "invalid_client" error

  @oidc4vc_rest_wallet_initiated
  Scenario Outline: OIDC credential issuance and verification Auth flow (Claims Expiry)
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using authorization code flow with wallet-initiated
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" waits for interaction succeeded event
    Then we wait 15 seconds
    And Verifier with profile "<verifierProfile>" requests expired interactions claims

    Examples:
      | issuerProfile                  | credentialType             | credentialTemplate               | verifierProfile      | presentationDefinitionID                     | fields                                                    |
      | bank_issuer/v1.0               | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                            |
      | i_myprofile_ud_es256k_jwt/v1.0 | PermanentResidentCard      | permanentResidentCardTemplateID  | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,registration_city,commuter_classification |
      | i_myprofile_cmtr_p256_ldp/v1.0 | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_ldp/v1.0 | lp403pb9-schema-match                        | schema_id                                                 |

  Scenario Outline: OIDC credential issuance and verification Pre Auth flow (Limit Disclosures enabled for JWT and LDP VC)
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then credential is issued
    And User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>" and receives "no matching credentials found" error
    Then we wait 15 seconds
    And Verifier with profile "<verifierProfile>" requests expired interactions claims

    Examples:
      | issuerProfile                  | credentialType         | credentialTemplate               | verifierProfile      | presentationDefinitionID                  | fields                                                       |
#      JWT issuer, JWT verifier, limit disclosure enabled in PD query.
      | i_myprofile_ud_es256k_jwt/v1.0 | CrudeProductCredential | crudeProductCredentialTemplateID | v_myprofile_jwt/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields | unit_of_measure_barrel,api_gravity,category,supplier_address |
#      LDP issuer, LDP verifier, limit disclosure enabled in PD query.
      | i_myprofile_cmtr_p256_ldp/v1.0 | CrudeProductCredential | crudeProductCredentialTemplateID | v_myprofile_ldp/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields | unit_of_measure_barrel,api_gravity,category,supplier_address |

  @oidc4vc_rest_wallet_initiated_unsupported_vp_token_format
  Scenario Outline: OIDC credential issuance and verification Pre Auth flow (OIDC4VP flow - unsupported vp_token format)
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then credential is issued
    And wallet configured to use hardcoded vp_token format "jwt" for OIDC4VP interaction
    And User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>" and receives "no matching credentials found" error
    Then we wait 15 seconds
    And Verifier with profile "<verifierProfile>" requests expired interactions claims

    Examples:
      | issuerProfile                  | credentialType         | credentialTemplate               | verifierProfile      | presentationDefinitionID                  | fields                                                       |
#     LDP issuer, LDP verifier, no limit disclosure and schema match in PD query.
      | i_myprofile_ud_es256k_jwt/v1.0 | CrudeProductCredential | crudeProductCredentialTemplateID | v_myprofile_ldp/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields | unit_of_measure_barrel,api_gravity,category,supplier_address |


  Scenario Outline: OIDC credential issuance without required role
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-non-issuer-1" and password "profile-user-non-issuer-1-pwd"
    And  User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"


    When User initiates credential issuance flow and receives "expected status code 200 but got status code 403" error
    Examples:
      | issuerProfile    | credentialType             | credentialTemplate         | verifierProfile      |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0 | UniversityDegreeCredential | universityDegreeTemplateID | v_myprofile_jwt/v1.0 |

  Scenario Outline: OIDC credential verification without required role
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And  User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-non-verifier-1" and password "profile-user-non-verifier-1-pwd"


    When User interacts with Wallet to initiate credential issuance using authorization code flow with client registration method "<clientRegistrationMethod>"
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>" and receives "expected status code 200 but got status code 403" error
    Examples:
      | issuerProfile    | credentialType             | clientRegistrationMethod | credentialTemplate         | verifierProfile      | presentationDefinitionID                  | fields         |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0 | UniversityDegreeCredential | dynamic                  | universityDegreeTemplateID | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id |

  @oidc4vc_rest_pre_auth_flow_client_attestation
  Scenario: OIDC credential pre-authorized code flow issuance and verification with client attestation
    Given Profile "i_myprofile_jwt_client_attestation/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And User holds credential "UniversityDegreeCredential" with templateID "universityDegreeTemplateID"
    And Profile "v_myprofile_jwt_client_attestation/v1.0" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow with client attestation enabled
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "v_myprofile_jwt_client_attestation/v1.0" profile with presentation definition ID "attestation-vc-single-field" and fields "degree_type_id"
    And Verifier with profile "v_myprofile_jwt_client_attestation/v1.0" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "v_myprofile_jwt_client_attestation/v1.0" requests deleted interactions claims
