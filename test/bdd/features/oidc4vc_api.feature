#
# Copyright Avast Software. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@oidc4vc_rest
Feature: OIDC4VC REST API

  Scenario Outline: OIDC credential issuance and verification Auth flow
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "<issuerProfile>" is authorized as a Profile user
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"

    When User interacts with Wallet to initiate credential issuance using authorization code flow with client registration method "<clientRegistrationMethod>"
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile for organization "test_org" with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier from organization "test_org" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier form organization "test_org" requests deleted interactions claims

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

  Scenario Outline: OIDC credential issuance and verification Pre Auth flow
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "<issuerProfile>" is authorized as a Profile user
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile for organization "test_org" with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier from organization "test_org" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier form organization "test_org" requests deleted interactions claims

    Examples:
      | issuerProfile                  | credentialType             | credentialTemplate               | verifierProfile      | presentationDefinitionID                     | fields                                                       |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0               | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                               |
#      SDJWT issuer, JWT verifier, limit disclosure and optional fields in PD query.
      | bank_issuer/v1.0               | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_jwt/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields    | unit_of_measure_barrel,api_gravity,category,supplier_address |
      | bank_issuer_sdjwt_v5/v1.0      | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_jwt/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields    | unit_of_measure_barrel,api_gravity,category,supplier_address |
#     JWT issuer, JWT verifier, no limit disclosure and optional fields in PD query.
      | i_myprofile_ud_es256k_jwt/v1.0 | PermanentResidentCard      | permanentResidentCardTemplateID  | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,commuter_classification,registration_city    |
#     LDP issuer, LDP verifier, no limit disclosure and schema match in PD query.
      | i_myprofile_cmtr_p256_ldp/v1.0 | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_ldp/v1.0 | lp403pb9-schema-match                        | schema_id                                                    |

  Scenario Outline: OIDC credential issuance and verification Pre Auth flow with trustlist (Success)
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "<issuerProfile>" is authorized as a Profile user
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile for organization "test_org" with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier from organization "test_org" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier form organization "test_org" requests deleted interactions claims
    Examples:
      | issuerProfile             | credentialType             | credentialTemplate               | verifierProfile                | presentationDefinitionID                  | fields                                                       |
      | bank_issuer_sdjwt_v5/v1.0 | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_jwt_whitelist/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields | unit_of_measure_barrel,api_gravity,category,supplier_address |
      | bank_issuer/v1.0          | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt_whitelist/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id                                               |

# Error cases

  Scenario Outline: OIDC credential issuance and verification Pre Auth flow with trustlist (Fail)
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "<issuerProfile>" is authorized as a Profile user
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile for organization "test_org" with presentation definition ID "<presentationDefinitionID>" and fields "<fields>" and receives "is not a member of trustlist" error
    Examples:
      | issuerProfile                  | credentialType             | credentialTemplate              | verifierProfile                | presentationDefinitionID                     | fields                                                    |
      | bank_issuer_sdjwt_v5/v1.0      | UniversityDegreeCredential | universityDegreeTemplateID      | v_myprofile_jwt_whitelist/v1.0 | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                            |
      | i_myprofile_ud_es256k_jwt/v1.0 | PermanentResidentCard      | permanentResidentCardTemplateID | v_myprofile_jwt_whitelist/v1.0 | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,registration_city,commuter_classification |

  Scenario: OIDC credential issuance and verification Pre Auth flow (Invalid Claims)
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "bank_issuer/v1.0" is authorized as a Profile user
    Then User interacts with Wallet to initiate credential issuance using pre authorization code flow with invalid claims

  @oidc4vc_rest_pre_auth_schema_validation_error
  Scenario: OIDC credential issuance and verification Pre Auth flow (Claims JSON schema validation error)
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "bank_issuer/v1.0" is authorized as a Profile user
    Then User interacts with Wallet to initiate credential issuance using pre authorization code flow with invalid claims schema

  @oidc4vc_rest_auth_schema_validation_error
  Scenario: OIDC credential issuance and verification Auth flow (Claims JSON schema validation error)
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "bank_issuer/v1.0" is authorized as a Profile user
    Then User interacts with Wallet to initiate credential issuance using authorization code flow with invalid claims schema

  Scenario: OIDC credential issuance and verification Pre Auth flow (Invalid Field in Presentation Definition)
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "i_myprofile_ud_es256k_jwt/v1.0" is authorized as a Profile user
    And   User holds credential "CrudeProductCredential" with templateID "crudeProductCredentialTemplateID"
    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then credential is issued
    And User interacts with Verifier and initiate OIDC4VP interaction under "v_myprofile_jwt/v1.0" profile for organization "test_org" with presentation definition ID "32f54163-no-limit-disclosure-optional-fields" and fields "lpr_category_id,commuter_classification,invalidfield" and receives "field invalidfield not found" error

  Scenario: OIDC credential issuance and verification Auth flow (Malicious attacker stealing auth code & calling token endpoint with it)
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "bank_issuer/v1.0" is authorized as a Profile user
    And   User holds credential "UniversityDegreeCredential" with templateID "universityDegreeTemplateID"
    Then Malicious attacker stealing auth code from User and using "malicious_attacker_id" ClientID makes /token request and receives "invalid_client" error

  Scenario: OIDC credential issuance and verification Pre Auth flow (issuer has pre-authorized_grant_anonymous_access_supported disabled)
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "i_disabled_preauth_without_client_id/v1.0" is authorized as a Profile user
    And   User holds credential "VerifiedEmployee" with templateID "templateID"
    Then User interacts with Wallet to initiate credential issuance using pre authorization code flow and receives "invalid_client" error

  Scenario Outline: OIDC credential issuance and verification Auth flow (Claims Expiry)
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "<issuerProfile>" is authorized as a Profile user
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    When User interacts with Wallet to initiate credential issuance using authorization code flow with wallet-initiated
    Then credential is issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile for organization "test_org" with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier form organization "test_org" waits for interaction succeeded event
    Then we wait 15 seconds
    And Verifier form organization "test_org" requests expired interactions claims

    Examples:
      | issuerProfile                  | credentialType             | credentialTemplate               | verifierProfile      | presentationDefinitionID                     | fields                                                    |
      | bank_issuer/v1.0               | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                            |
      | i_myprofile_ud_es256k_jwt/v1.0 | PermanentResidentCard      | permanentResidentCardTemplateID  | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,registration_city,commuter_classification |
      | i_myprofile_cmtr_p256_ldp/v1.0 | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_ldp/v1.0 | lp403pb9-schema-match                        | schema_id                                                 |

  Scenario Outline: OIDC credential issuance and verification Pre Auth flow (Limit Disclosures enabled for JWT and LDP VC)
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "<issuerProfile>" is authorized as a Profile user
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then credential is issued
    And User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile for organization "test_org" with presentation definition ID "<presentationDefinitionID>" and fields "<fields>" and receives "query vc using presentation definition: no result found" error
    Then we wait 15 seconds
    And Verifier form organization "test_org" requests expired interactions claims

    Examples:
      | issuerProfile                  | credentialType         | credentialTemplate               | verifierProfile      | presentationDefinitionID                  | fields                                                       |
#      JWT issuer, JWT verifier, limit disclosure enabled in PD query.
      | i_myprofile_ud_es256k_jwt/v1.0 | CrudeProductCredential | crudeProductCredentialTemplateID | v_myprofile_jwt/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields | unit_of_measure_barrel,api_gravity,category,supplier_address |
#      LDP issuer, LDP verifier, limit disclosure enabled in PD query.
      | i_myprofile_cmtr_p256_ldp/v1.0 | CrudeProductCredential | crudeProductCredentialTemplateID | v_myprofile_ldp/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields | unit_of_measure_barrel,api_gravity,category,supplier_address |
#
  Scenario Outline: OIDC credential issuance and verification Pre Auth flow (OIDC4VP flow - unsupported vp_token format)
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "<issuerProfile>" is authorized as a Profile user
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then credential is issued
    And wallet configured to use hardcoded vp_token format "jwt" for OIDC4VP interaction
    And User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile for organization "test_org" with presentation definition ID "<presentationDefinitionID>" and fields "<fields>" and receives "profile does not support jwt vp_token format" error
    Then we wait 15 seconds
    And Verifier form organization "test_org" requests expired interactions claims

    Examples:
      | issuerProfile                  | credentialType         | credentialTemplate               | verifierProfile      | presentationDefinitionID | fields    |
#     LDP issuer, LDP verifier, no limit disclosure and schema match in PD query.
      | i_myprofile_cmtr_p256_ldp/v1.0 | CrudeProductCredential | crudeProductCredentialTemplateID | v_myprofile_ldp/v1.0 | lp403pb9-schema-match    | schema_id |

