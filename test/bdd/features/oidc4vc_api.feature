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
    Then "1" credentials are issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile                         | credentialType             | clientRegistrationMethod | credentialTemplate               | verifierProfile      | presentationDefinitionID                     | fields                                                       |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0                      | UniversityDegreeCredential | dynamic                  | universityDegreeTemplateID       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                               |
#      SDJWT issuer, JWT verifier, limit disclosure and optional fields in PD query.
      | bank_issuer/v1.0                      | CrudeProductCredential     | discoverable             | crudeProductCredentialTemplateID | v_myprofile_jwt/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields    | unit_of_measure_barrel,api_gravity,category,supplier_address |
#     JWT issuer, JWT verifier, no limit disclosure and optional fields in PD query.
      | i_myprofile_ud_es256k_jwt/v1.0        | PermanentResidentCard      | pre-registered           | permanentResidentCardTemplateID  | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,registration_city,commuter_classification    |
#     JWT issuer with status list feature disabled, JWT verifier, no limit disclosure and optional fields in PD query.
      | i_myprofile_ud_es256k_jwt_no_csl/v1.0 | PermanentResidentCard      | pre-registered           | permanentResidentCardTemplateID  | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,registration_city,commuter_classification    |
#     LDP Data Integrity issuer, LDP verifier, no limit disclosure and schema match in PD query.
      | i_myprofile_ud_di_ecdsa-2019/v1.0     | PermanentResidentCard      | pre-registered           | permanentResidentCardTemplateID  | v_myprofile_ldp/v1.0 | 062759b1-no-limit-disclosure-optional-fields | lpr_category_id,registration_city,commuter_classification    |
#     LDP issuer, LDP verifier, no limit disclosure and schema match in PD query.
      | i_myprofile_cmtr_p256_ldp/v1.0        | CrudeProductCredential     | pre-registered           | crudeProductCredentialTemplateID | v_myprofile_ldp/v1.0 | lp403pb9-schema-match                        | schema_id                                                    |

  @oidc4vc_rest_auth_flow_v2
  Scenario Outline: OIDC credential issuance and verification Auth flow with credential model 2.0
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And  User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using authorization code flow with client registration method "<clientRegistrationMethod>"
    Then "1" credentials are issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile                         | credentialType             | clientRegistrationMethod | credentialTemplate               | verifierProfile      | presentationDefinitionID                     | fields                                                       |
#     SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer_v2/v1.0                      | UniversityDegreeCredential | dynamic                  | universityDegreeTemplateID       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                               |
#     SDJWT issuer, JWT verifier, limit disclosure and optional fields in PD query.
      | bank_issuer_v2/v1.0                      | CrudeProductCredential     | discoverable             | crudeProductCredentialTemplateID | v_myprofile_jwt/v1.0 | 3c8b1d9a-limit-disclosure-optional-fields    | unit_of_measure_barrel,api_gravity,category,supplier_address |
#     JWT issuer, JWT verifier, no limit disclosure and optional fields in PD query.
      | i_myprofile_ud_es256k_jwt_v2/v1.0        | PermanentResidentCard      | pre-registered           | permanentResidentCardTemplateID  | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,registration_city,commuter_classification    |

  @oidc4vc_rest_auth_flow_batch_credential_configuration_id
  Scenario Outline: OIDC Batch credential issuance and verification Auth flow (request all credentials by credentialConfigurationID)
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate batch credential issuance using authorization code flow with credential configuration ID "<credentialConfigurationID>"
    Then "<issuedCredentialsAmount>" credentials are issued
    Then expected credential count for vp flow is "<expectedCredentialCountVPFlow>"
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile    | credentialConfigurationID                                                                        | issuedCredentialsAmount | verifierProfile      | presentationDefinitionID                  | fields         | expectedCredentialCountVPFlow |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0 | UniversityDegreeCredentialIdentifier,CrudeProductCredentialIdentifier,VerifiedEmployeeIdentifier | 3                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | 1                             |
      | bank_issuer/v1.0 | UniversityDegreeCredentialIdentifier,CrudeProductCredentialIdentifier                            | 2                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | 1                             |

  @oidc4vc_rest_auth_flow_batch_credential_filters
  Scenario Outline: OIDC Batch credential issuance and verification Auth flow (request all credentials by credential type)
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And  User holds credential "<credentialType>" with templateID "nil"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate batch credential issuance using authorization code flow
    Then "<issuedCredentialsAmount>" credentials are issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile    | credentialType                                                     | issuedCredentialsAmount | verifierProfile      | presentationDefinitionID                  | fields         |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0 | UniversityDegreeCredential,CrudeProductCredential,VerifiedEmployee | 3                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id |
      | bank_issuer/v1.0 | UniversityDegreeCredential,CrudeProductCredential                  | 2                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id |

  @oidc4vc_rest_auth_flow_batch_additional_scopes
  Scenario Outline: OIDC Batch credential issuance and verification Auth flow (request all credentials by scopes)
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate batch credential issuance using authorization code flow with scopes "<scopes>"
    Then "<issuedCredentialsAmount>" credentials are issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile    | scopes                                                                                   | issuedCredentialsAmount | verifierProfile      | presentationDefinitionID                  | fields         |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0 | UniversityDegreeCredential_001,CrudeProductCredential_001,VerifiedEmployeeCredential_001 | 3                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id |
      | bank_issuer/v1.0 | UniversityDegreeCredential_001,CrudeProductCredential_001                                | 2                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id |

  @oidc4vc_rest_preauth_flow_batch_credential_filters
  Scenario Outline: OIDC Batch credential issuance and verification Pre Auth flow (request all credentials by credential type)
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And  User holds credential "<credentialType>" with templateID "nil"
    And  User wants to make credentials request based on credential offer "<useCredentialOfferForCredentialRequest>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate batch credential issuance using pre authorization code flow
    Then "<issuedCredentialsAmount>" credentials are issued
    Then expected credential count for vp flow is "<expectedCredentialCountVPFlow>"
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims
#     In examples below Initiate Issuence request and Credential request are based on credentialType param.
    Examples:
      | issuerProfile    | credentialType                                                     | useCredentialOfferForCredentialRequest | issuedCredentialsAmount | verifierProfile      | presentationDefinitionID                  | fields         | expectedCredentialCountVPFlow |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0 | UniversityDegreeCredential,CrudeProductCredential,VerifiedEmployee | false                                  | 3                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | 1                             |
      | bank_issuer/v1.0 | UniversityDegreeCredential,CrudeProductCredential                  | false                                  | 2                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | 1                             |
#     Same VC type
      | bank_issuer/v1.0 | UniversityDegreeCredential,UniversityDegreeCredential              | false                                  | 2                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | 2                             |
      | bank_issuer/v1.0 | UniversityDegreeCredential,UniversityDegreeCredential              | true                                   | 2                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | 2                             |

  @oidc4vc_rest_auth_flow_credential_conf_id
  Scenario Outline: OIDC credential issuance and verification Auth flow using credential configuration ID to request specific credential type
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And  User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using authorization code flow with credential configuration ID "<credentialConfigurationID>"
    Then "1" credentials are issued
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
    Then "1" credentials are issued
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
    Then "1" credentials are issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile                  | credentialType             | credentialTemplate               | verifierProfile           | presentationDefinitionID                     | fields                                                       | proofType |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0               | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt/v1.0      | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                               | jwt       |
      | bank_issuer/v1.0               | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt/v1.0      | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                               | ldp_vc    |
      | bank_issuer/v1.0               | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt/v1.0      | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                               | cwt       |
      | acme_issuer/v1.0               | UniversityDegreeCredential | universityDegreeTemplateID       | v_myprofile_jwt/v1.0      | 32f54163-no-limit-disclosure-single-field    | degree_type_id                                               | jwt       |
##      SDJWT issuer, JWT verifier, limit disclosure and optional fields in PD query.
      | bank_issuer/v1.0               | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_jwt/v1.0      | 3c8b1d9a-limit-disclosure-optional-fields    | unit_of_measure_barrel,api_gravity,category,supplier_address | jwt       |
      | bank_issuer_sdjwt_v5/v1.0      | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_jwt/v1.0      | 3c8b1d9a-limit-disclosure-optional-fields    | unit_of_measure_barrel,api_gravity,category,supplier_address | jwt       |
##     JWT issuer, JWT verifier, no limit disclosure and optional fields in PD query.
      | i_myprofile_ud_es256k_jwt/v1.0 | PermanentResidentCard      | permanentResidentCardTemplateID  | v_myprofile_jwt/v1.0      | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,commuter_classification,registration_city    | jwt       |
##     LDP issuer, LDP verifier, no limit disclosure and schema match in PD query.
      | i_myprofile_cmtr_p256_ldp/v1.0 | CrudeProductCredential     | crudeProductCredentialTemplateID | v_myprofile_ldp/v1.0      | lp403pb9-schema-match                        | schema_id                                                    | jwt       |
      | awesome_cwt/v1.0               | PermanentResidentCard      | permanentResidentCardTemplateID  | awesome_cwt_verifier/v1.0 | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,commuter_classification,registration_city    | cwt       |
      | i_myprofile_ud_es256k_jwt/v1.0 | PermanentResidentCard      | permanentResidentCardTemplateID  | v_myprofile_jwt/v1.0      | 32f54163-no-limit-disclosure-optional-fields | lpr_category_id,commuter_classification,registration_city    | cwt       |

  @oidc4vc_rest_pre_auth_flow_credential_refresh
  Scenario Outline: OIDC credential issuance and verification Pre Auth flow
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And  User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And proofType is "<proofType>"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then "1" credentials are issued
    Then ensure credential refresh service is set

    Then wallet ensures that no credential refresh available
    Then issuer send requests to initiate credential refresh
    ## expected two times for test, as we should invalidate previous request
    Then issuer send requests to initiate credential refresh
    Then wallet refreshes credentials
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile    | credentialType             | credentialTemplate         | verifierProfile      | presentationDefinitionID                  | fields         | proofType |
      | bank_issuer/v1.0 | UniversityDegreeCredential | universityDegreeTemplateID | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | jwt       |

  @oidc4vc_rest_pre_auth_flow_compose
  Scenario Outline: OIDC credential issuance and verification Pre Auth flow
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And proofType is "<proofType>"
    And initiateIssuanceVersion is "2"
    And credentialCompose is active with "<credentialEncoded>"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then "1" credentials are issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile                | credentialType             | credentialTemplate | verifierProfile      | presentationDefinitionID                  | fields         | proofType | credentialEncoded                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
      | acme_issuer/v1.0             | UniversityDegreeCredential |                    | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | jwt       | ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsCiAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiLAogICAgImh0dHBzOi8vdzNpZC5vcmcvdmMvc3RhdHVzLWxpc3QvMjAyMS92MSIKICBdLAogICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgImlkIjogInVybjp1dWlkOjViYjIwNTU4LTI1Y2UtNDBiNS04MGZjLThhZjY5MWVlZGNjZSIsCiAgICAic3RhdHVzTGlzdENyZWRlbnRpYWwiOiAiaHR0cDovL3ZjLXJlc3QtZWNoby50cnVzdGJsb2MubG9jYWw6ODA3NS9pc3N1ZXIvZ3JvdXBzL2dyb3VwX2FjbWVfaXNzdWVyL2NyZWRlbnRpYWxzL3N0YXR1cy8wNmIxM2U5Mi0yN2E2LTRiNzYtOTk3Ny02ZWNlMjA3NzgzZGQiLAogICAgInN0YXR1c0xpc3RJbmRleCI6ICI2NTQ4IiwKICAgICJzdGF0dXNQdXJwb3NlIjogInJldm9jYXRpb24iLAogICAgInR5cGUiOiAiU3RhdHVzTGlzdDIwMjFFbnRyeSIKICB9LAogICJjcmVkZW50aWFsU3ViamVjdCI6IHsKICAgICJkZWdyZWUiOiB7CiAgICAgICJkZWdyZWUiOiAiTUlUIiwKICAgICAgInR5cGUiOiAiQmFjaGVsb3JEZWdyZWUiCiAgICB9LAogICAgImlkIjogImRpZDppb246RWlCeVFBeFhtT0FFTTdUbEVVRzl1NlJyMnJzNVFDTHh1T2ZWbE5ONXpUM1JtUTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKaFpHUXRjSFZpYkdsakxXdGxlWE1pTENKd2RXSnNhV05MWlhseklqcGJleUpwWkNJNklsOXVWVGx5YmtGcGNIZzNNRmhYU0RSS2RVcDNUMVZwV2paNFNVWk5ZVEZuUm1oS1VWVXdWSFoyTTFFaUxDSndkV0pzYVdOTFpYbEtkMnNpT25zaVkzSjJJam9pVUMwek9EUWlMQ0pyYVdRaU9pSmZibFU1Y201QmFYQjROekJZVjBnMFNuVktkMDlWYVZvMmVFbEdUV0V4WjBab1NsRlZNRlIyZGpOUklpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaU5sYzNkSEZhTVhabFRUZFpTRTU1ZEROME9YaE1PVGRNVDBoelp6a3libTV3WDJSc2FXTlFjVlJsY2pSdFNYaFplVFZ4TTA1MmVVa3djekkxV2tsRk9DSXNJbmtpT2lKRGExUlhaaTFZVlZwNkxWZDJOekl0TlhCdk9XZHBjblo2U25kNE1uRlRRMGt5Wm1GNWJIZFhjbXR0YW5wWE16RkVjV0ZIY2paRldrUXRkVmxEVTJkT0luMHNJbkIxY25CdmMyVnpJanBiSW1GMWRHaGxiblJwWTJGMGFXOXVJaXdpWVhOelpYSjBhVzl1VFdWMGFHOWtJbDBzSW5SNWNHVWlPaUpLYzI5dVYyVmlTMlY1TWpBeU1DSjlYWDFkTENKMWNHUmhkR1ZEYjIxdGFYUnRaVzUwSWpvaVJXbERNbWh0YzJSRk5IRk9kMjFUUTFCbU1qRjFNRXg2UWtodmMzQldVRkZzT1ZKdFRHczNORloxWnpWcmR5SjlMQ0p6ZFdabWFYaEVZWFJoSWpwN0ltUmxiSFJoU0dGemFDSTZJa1ZwUVMxWk9YVjBUVTVoYVVoVlIxcHROVEJtUVZKamNWTmFjVWRCTXpkNlFsWlVOVVk0UzBsdFh6TlRka0VpTENKeVpXTnZkbVZ5ZVVOdmJXMXBkRzFsYm5RaU9pSkZhVUpSYlVOaWRsOVZRelZSUmtOMk9VTndiMUpQYVZNNWJIWkNkbmR1WTJsWkxWOTRjbEU0U1RKdlIwSm5JbjBzSW5SNWNHVWlPaUpqY21WaGRHVWlmUSIsCiAgICAibmFtZSI6ICJKYXlkZW4gRG9lIiwKICAgICJzcG91c2UiOiAiZGlkOmV4YW1wbGU6YzI3NmUxMmVjMjFlYmZlYjFmNzEyZWJjNmYxIgogIH0sCiAgImV4cGlyYXRpb25EYXRlIjogIjIwMjUtMDMtMThUMjI6MDY6MzEuMzQyNTAxMDZaIiwKICAiaWQiOiAidXJuOnV1aWQ6N2NiYjliYTItMzgwMS00Nzg2LWI3YzEtYWQyZDQyOTI0M2E4IiwKICAiaXNzdWFuY2VEYXRlIjogIjIwMjQtMDMtMThUMjI6MDY6MzEuMzc1NDM0MTMxWiIsCiAgImlzc3VlciI6IHsKICAgICJpZCI6ICJkaWQ6aW9uOkVpQW9hSEpZRjJRNms5eml5aDRQRHJ1c0ladE5VS20xLWFGckF2clBEQ0VNU1E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSmhaR1F0Y0hWaWJHbGpMV3RsZVhNaUxDSndkV0pzYVdOTFpYbHpJanBiZXlKcFpDSTZJbU0xTkdRME1qZzJMV0l5TmpNdE5ESTNNQzFoTURNeExUVXlPVEppWXpSak5qUmpaQ0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpsSWpvaVFWRkJRaUlzSW10cFpDSTZJbU0xTkdRME1qZzJMV0l5TmpNdE5ESTNNQzFoTURNeExUVXlPVEppWXpSak5qUmpaQ0lzSW10MGVTSTZJbEpUUVNJc0ltNGlPaUp1V1RCaU5tRkdURTVWYW1RM2VFRnBiVnA0ZFVnd1prNVNUVWN6WldOSFdHOVpTM1JSV0RSMVMxRmpjMWxaVTI1R2FFRkRlRGhtYW5Cbk5qSkplVnBDZFZSUVlUWnVaM04yWDA1UlFraFVXVWxNUmpKUldWVlFhVFJRVkVzdGVVRTNUbVJQU2xad05VRkZWelZ5YzNsc1pUZ3dTeTFQVUdsVVVXMUtSMng1VWpoSlVrWklOazl0TTNNMllYTnRXVmw1WmtrdExXdFJaVGhJYTBkMGJYYzNUR2xpVldWWlduZDNSemxJU1d4NlNEUlFObWhJVDNOVVpsaGhSRmwyYkRVM1dXcDFibWd5Y1ZVeVlXbFhSRms1UVdsVVVrSnBiVXhDYUVsdVpuWTBOVTVZZVRsMWQzSkdPWE5aYkZodWJHZDViVlZUTVZGV2NUYzVWUzFsYmt0bVJYTXpSMnMyUlVSaVYzSkhiWHBIY0hSUFpHcHpkRWt3T1dWNGFWUklPRXRyZG5oT1JXaFFla3hrZW5rd1VGTmxSV1o0WDJsVFdXeE1aRmxKUmtWVU4yb3hNVTV2TFRGeU1rVjZRa05wVVRWdWRGSXhNMUVpZlN3aWNIVnljRzl6WlhNaU9sc2lZWFYwYUdWdWRHbGpZWFJwYjI0aUxDSmhjM05sY25ScGIyNU5aWFJvYjJRaVhTd2lkSGx3WlNJNklrcHpiMjVYWldKTFpYa3lNREl3SW4xZGZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVORVJsRlFabmhTUm5Oc2NrRkliVm80YVhOUWJFNDRRelpLVW1SemVuUTBabkkwYURsSU5HUm1NVlpuSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEJTRE14TkZkcVJUTkJhVFJoTFhNeVNtOUhjWFpqUzFWcFRFUmZNVEpWWjNWeFkwWTFiVWR6Um5aMFp5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFTMXBka1pxVFRaTGRteDJZVXRVT0dkQ2EzQkphelpMWmt4dk9VbDVNR28wWVdobWFpMXJUMGwyV2xFaWZTd2lkSGx3WlNJNkltTnlaV0YwWlNKOSIsCiAgICAibmFtZSI6ICJBY21lIElzc3VlciIKICB9LAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVDcmVkZW50aWFsIiwKICAgICJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCIKICBdCn0= |
      | acme_issuer_no_template/v1.0 | UniversityDegreeCredential |                    | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | jwt       | ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsCiAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiLAogICAgImh0dHBzOi8vdzNpZC5vcmcvdmMvc3RhdHVzLWxpc3QvMjAyMS92MSIKICBdLAogICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgImlkIjogInVybjp1dWlkOjViYjIwNTU4LTI1Y2UtNDBiNS04MGZjLThhZjY5MWVlZGNjZSIsCiAgICAic3RhdHVzTGlzdENyZWRlbnRpYWwiOiAiaHR0cDovL3ZjLXJlc3QtZWNoby50cnVzdGJsb2MubG9jYWw6ODA3NS9pc3N1ZXIvZ3JvdXBzL2dyb3VwX2FjbWVfaXNzdWVyL2NyZWRlbnRpYWxzL3N0YXR1cy8wNmIxM2U5Mi0yN2E2LTRiNzYtOTk3Ny02ZWNlMjA3NzgzZGQiLAogICAgInN0YXR1c0xpc3RJbmRleCI6ICI2NTQ4IiwKICAgICJzdGF0dXNQdXJwb3NlIjogInJldm9jYXRpb24iLAogICAgInR5cGUiOiAiU3RhdHVzTGlzdDIwMjFFbnRyeSIKICB9LAogICJjcmVkZW50aWFsU3ViamVjdCI6IHsKICAgICJkZWdyZWUiOiB7CiAgICAgICJkZWdyZWUiOiAiTUlUIiwKICAgICAgInR5cGUiOiAiQmFjaGVsb3JEZWdyZWUiCiAgICB9LAogICAgImlkIjogImRpZDppb246RWlCeVFBeFhtT0FFTTdUbEVVRzl1NlJyMnJzNVFDTHh1T2ZWbE5ONXpUM1JtUTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKaFpHUXRjSFZpYkdsakxXdGxlWE1pTENKd2RXSnNhV05MWlhseklqcGJleUpwWkNJNklsOXVWVGx5YmtGcGNIZzNNRmhYU0RSS2RVcDNUMVZwV2paNFNVWk5ZVEZuUm1oS1VWVXdWSFoyTTFFaUxDSndkV0pzYVdOTFpYbEtkMnNpT25zaVkzSjJJam9pVUMwek9EUWlMQ0pyYVdRaU9pSmZibFU1Y201QmFYQjROekJZVjBnMFNuVktkMDlWYVZvMmVFbEdUV0V4WjBab1NsRlZNRlIyZGpOUklpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaU5sYzNkSEZhTVhabFRUZFpTRTU1ZEROME9YaE1PVGRNVDBoelp6a3libTV3WDJSc2FXTlFjVlJsY2pSdFNYaFplVFZ4TTA1MmVVa3djekkxV2tsRk9DSXNJbmtpT2lKRGExUlhaaTFZVlZwNkxWZDJOekl0TlhCdk9XZHBjblo2U25kNE1uRlRRMGt5Wm1GNWJIZFhjbXR0YW5wWE16RkVjV0ZIY2paRldrUXRkVmxEVTJkT0luMHNJbkIxY25CdmMyVnpJanBiSW1GMWRHaGxiblJwWTJGMGFXOXVJaXdpWVhOelpYSjBhVzl1VFdWMGFHOWtJbDBzSW5SNWNHVWlPaUpLYzI5dVYyVmlTMlY1TWpBeU1DSjlYWDFkTENKMWNHUmhkR1ZEYjIxdGFYUnRaVzUwSWpvaVJXbERNbWh0YzJSRk5IRk9kMjFUUTFCbU1qRjFNRXg2UWtodmMzQldVRkZzT1ZKdFRHczNORloxWnpWcmR5SjlMQ0p6ZFdabWFYaEVZWFJoSWpwN0ltUmxiSFJoU0dGemFDSTZJa1ZwUVMxWk9YVjBUVTVoYVVoVlIxcHROVEJtUVZKamNWTmFjVWRCTXpkNlFsWlVOVVk0UzBsdFh6TlRka0VpTENKeVpXTnZkbVZ5ZVVOdmJXMXBkRzFsYm5RaU9pSkZhVUpSYlVOaWRsOVZRelZSUmtOMk9VTndiMUpQYVZNNWJIWkNkbmR1WTJsWkxWOTRjbEU0U1RKdlIwSm5JbjBzSW5SNWNHVWlPaUpqY21WaGRHVWlmUSIsCiAgICAibmFtZSI6ICJKYXlkZW4gRG9lIiwKICAgICJzcG91c2UiOiAiZGlkOmV4YW1wbGU6YzI3NmUxMmVjMjFlYmZlYjFmNzEyZWJjNmYxIgogIH0sCiAgImV4cGlyYXRpb25EYXRlIjogIjIwMjUtMDMtMThUMjI6MDY6MzEuMzQyNTAxMDZaIiwKICAiaWQiOiAidXJuOnV1aWQ6N2NiYjliYTItMzgwMS00Nzg2LWI3YzEtYWQyZDQyOTI0M2E4IiwKICAiaXNzdWFuY2VEYXRlIjogIjIwMjQtMDMtMThUMjI6MDY6MzEuMzc1NDM0MTMxWiIsCiAgImlzc3VlciI6IHsKICAgICJpZCI6ICJkaWQ6aW9uOkVpQW9hSEpZRjJRNms5eml5aDRQRHJ1c0ladE5VS20xLWFGckF2clBEQ0VNU1E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSmhaR1F0Y0hWaWJHbGpMV3RsZVhNaUxDSndkV0pzYVdOTFpYbHpJanBiZXlKcFpDSTZJbU0xTkdRME1qZzJMV0l5TmpNdE5ESTNNQzFoTURNeExUVXlPVEppWXpSak5qUmpaQ0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpsSWpvaVFWRkJRaUlzSW10cFpDSTZJbU0xTkdRME1qZzJMV0l5TmpNdE5ESTNNQzFoTURNeExUVXlPVEppWXpSak5qUmpaQ0lzSW10MGVTSTZJbEpUUVNJc0ltNGlPaUp1V1RCaU5tRkdURTVWYW1RM2VFRnBiVnA0ZFVnd1prNVNUVWN6WldOSFdHOVpTM1JSV0RSMVMxRmpjMWxaVTI1R2FFRkRlRGhtYW5Cbk5qSkplVnBDZFZSUVlUWnVaM04yWDA1UlFraFVXVWxNUmpKUldWVlFhVFJRVkVzdGVVRTNUbVJQU2xad05VRkZWelZ5YzNsc1pUZ3dTeTFQVUdsVVVXMUtSMng1VWpoSlVrWklOazl0TTNNMllYTnRXVmw1WmtrdExXdFJaVGhJYTBkMGJYYzNUR2xpVldWWlduZDNSemxJU1d4NlNEUlFObWhJVDNOVVpsaGhSRmwyYkRVM1dXcDFibWd5Y1ZVeVlXbFhSRms1UVdsVVVrSnBiVXhDYUVsdVpuWTBOVTVZZVRsMWQzSkdPWE5aYkZodWJHZDViVlZUTVZGV2NUYzVWUzFsYmt0bVJYTXpSMnMyUlVSaVYzSkhiWHBIY0hSUFpHcHpkRWt3T1dWNGFWUklPRXRyZG5oT1JXaFFla3hrZW5rd1VGTmxSV1o0WDJsVFdXeE1aRmxKUmtWVU4yb3hNVTV2TFRGeU1rVjZRa05wVVRWdWRGSXhNMUVpZlN3aWNIVnljRzl6WlhNaU9sc2lZWFYwYUdWdWRHbGpZWFJwYjI0aUxDSmhjM05sY25ScGIyNU5aWFJvYjJRaVhTd2lkSGx3WlNJNklrcHpiMjVYWldKTFpYa3lNREl3SW4xZGZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVORVJsRlFabmhTUm5Oc2NrRkliVm80YVhOUWJFNDRRelpLVW1SemVuUTBabkkwYURsSU5HUm1NVlpuSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEJTRE14TkZkcVJUTkJhVFJoTFhNeVNtOUhjWFpqUzFWcFRFUmZNVEpWWjNWeFkwWTFiVWR6Um5aMFp5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFTMXBka1pxVFRaTGRteDJZVXRVT0dkQ2EzQkphelpMWmt4dk9VbDVNR28wWVdobWFpMXJUMGwyV2xFaWZTd2lkSGx3WlNJNkltTnlaV0YwWlNKOSIsCiAgICAibmFtZSI6ICJBY21lIElzc3VlciIKICB9LAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVDcmVkZW50aWFsIiwKICAgICJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCIKICBdCn0= |

  @oidc4vc_rest_pre_auth_flow_compose_with_attachment
  Scenario Outline: OIDC credential issuance and verification Pre Auth flow (attachment evidence)
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "<credentialType>" with templateID ""
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And proofType is "<proofType>"
    And initiateIssuanceVersion is "2"
    And credentialCompose is active with "<credentialEncoded>"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then "1" credentials are issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And expected attachment for vp flow is "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+CjxzdmcgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIiB4bWxuczpjYz0iaHR0cDovL2NyZWF0aXZlY29tbW9ucy5vcmcvbnMjIiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiIHhtbG5zOnN2Zz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmVyc2lvbj0iMS4xIiB2aWV3Qm94PSIwIDAgNzIgNDgiIGlkPSJzdmcxNjU5IiB3aWR0aD0iNzIiIGhlaWdodD0iNDgiPgogIDxtZXRhZGF0YSBpZD0ibWV0YWRhdGEzMTE2Ij4KICAgIDxyZGY6UkRGPgogICAgICA8Y2M6V29yayByZGY6YWJvdXQ9IiI+CiAgICAgICAgPGRjOmZvcm1hdD5pbWFnZS9zdmcreG1sPC9kYzpmb3JtYXQ+CiAgICAgICAgPGRjOnR5cGUgcmRmOnJlc291cmNlPSJodHRwOi8vcHVybC5vcmcvZGMvZGNtaXR5cGUvU3RpbGxJbWFnZSIgLz4KICAgICAgICA8ZGM6dGl0bGU+VzNDPC9kYzp0aXRsZT4KICAgICAgPC9jYzpXb3JrPgogICAgPC9yZGY6UkRGPgogIDwvbWV0YWRhdGE+CiAgPGRlZnMgaWQ9ImRlZnMzMTE0IiAvPgogIDxyZWN0IGZpbGwtcnVsZT0iZXZlbm9kZCIgd2lkdGg9IjcyIiBmaWxsPSIjZmZmZmZmIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGhlaWdodD0iNDgiIGlkPSJyZWN0MTYzOSIgeD0iMCIgeT0iMCIgc3R5bGU9ImltYWdlLXJlbmRlcmluZzpvcHRpbWl6ZVF1YWxpdHk7c2hhcGUtcmVuZGVyaW5nOmdlb21ldHJpY1ByZWNpc2lvbjt0ZXh0LXJlbmRlcmluZzpnZW9tZXRyaWNQcmVjaXNpb24iIC8+CiAgPHBhdGggZmlsbD0iIzAwNWE5YyIgZD0ibSAyLjAzMjQ1Myw4LjAwNTQ1MyA5LjUzMTI1LDMyLjE2OTkyMiBoIDAuMzk2NDg1IGwgNS45NTcwMzEsLTE5LjkzNTU0NyA1Ljk1ODk4NCwxOS45MzU1NDcgaCAwLjM5NjQ4NSBsIDcuMTQyNTc4LC0yNC4xMDU0NjkgYyAxLjM2NDEzNiwtNC42MDM2MDIgMC42ODczMDgsLTQuMDkzNzUgNC43NTc4MTIsLTQuMDkzNzUgSCAzOS41MzA1IGwgLTYuNjM2NzE5LDExLjUxOTUzMiBoIDIuNjY0MDYzIGMgMS43MjE2MDcsMCAzLjUzNDI4MSwwLjYyMTIzNCA0LjQ4ODI4MSwxLjg2NTIzNCAwLjEzMzY0OCwwLjE3MjYwMiAwLjI1Mzc0NywwLjM2MDQ3OCAwLjM2NTIzNCwwLjU1NjY0IDAuMDI1ODMsMC4wNDUxOSAwLjA0OTU1LDAuMDkyMjQgMC4wNzQyMiwwLjEzODY3MiAwLjEwNDkxOSwwLjE5ODU5NyAwLjIwMjkwNiwwLjQwNDE5MyAwLjI4NzExLDAuNjI1IDAuMzM0Njk5LDAuODc4MTk0IDAuNTAzOTA2LDEuOTMzMjY1IDAuNTAzOTA2LDMuMTY3OTY5IDAsMS43NDggLTAuMzg0MzQ0LDMuMjQzMjgxIC0xLjE1MjM0NCw0LjQ4ODI4MSAtMC4yMDg0ODMsMC4zMzc2OTkgLTAuNDMwMjMxLDAuNjI1MDY4IC0wLjY2NDA2MiwwLjg3MTA5NCAtMC4xNDk1NjQsMC4xNTczNjEgLTAuMzA1MTA1LDAuMjkzODgzIC0wLjQ2NDg0NCwwLjQxNDA2MyAtMC4wMTM0MywwLjAxMDA1IC0wLjAyNzUxLDAuMDE5NTEgLTAuMDQxMDIsMC4wMjkzIC0wLjE2Mjg3LDAuMTE4NzEgLTAuMzI4NDc5LDAuMjIwNTM2IC0wLjUwMTk1MywwLjMwMDc4MSAtMC4xNTgxMTIsMC4wNzMxNCAtMC4zMjMyMTQsMC4xMjUgLTAuNDkwMjM0LDAuMTY2MDE1IC0wLjA0MjY2LDAuMDEwMzkgLTAuMDg1NjgsMC4wMTkwNCAtMC4xMjg5MDcsMC4wMjczNCAtMC4xNzE4MDMsMC4wMzMyOCAtMC4zNDYyNDMsMC4wNTY2NCAtMC41MjczNDMsMC4wNTY2NCAtMC4wMDgxLDAgLTAuMDE1MzcsLTAuMDAxOSAtMC4wMjM0NCwtMC4wMDIgLTAuMDA4MSwtNC4xZS01IC0wLjAxNTM5LC0wLjAwMTkgLTAuMDIzNDQsLTAuMDAyIC0wLjAwNDEsLTMuOWUtNSAtMC4wMDc4LC0wLjAwMTUgLTAuMDExNzIsLTAuMDAyIC0wLjAwOTQsLTEuMThlLTQgLTAuMDE3OTksLTAuMDAxOCAtMC4wMjczNCwtMC4wMDIgLTAuMjM4MTg0LC0wLjAwNDMgLTAuNDcxMjkxLC0wLjAyMjQgLTAuNjk1MzEyLC0wLjA2MjUgLTAuMDAxMywtMi4yNmUtNCAtMC4wMDI3LDIuMjdlLTQgLTAuMDAzOSwwIC0wLjA2MTI5LC0wLjAxMTAzIC0wLjExNzUwNSwtMC4wMzUxMSAtMC4xNzc3MzQsLTAuMDQ4ODMgLTAuMDEyNTQsLTAuMDAyOCAtMC4wMjQ5MywtMC4wMDU5IC0wLjAzNzExLC0wLjAwOTggLTAuMDE1MjgsLTAuMDAzNyAtMC4wMjk3MSwtMC4wMDk4IC0wLjA0NDkyLC0wLjAxMzY3IC0wLjE1MjgzOCwtMC4wMzU0NiAtMC4zMDYzMTEsLTAuMDY5NjUgLTAuNDUxMTcyLC0wLjEyNSAtMC4yMjgyOTIsLTAuMDg3MjMgLTAuNDQ3MDk5LC0wLjE5NTYwMyAtMC42NTgyMDMsLTAuMzI2MTcyIEMgMzQuOTQwNDksMzUuNDc4Mzk5IDM0LjczNzkzNSwzNS4zMjYxMDEgMzQuNTQ0MTcyLDM1LjE1MTkzOCAzNC4xMjk5MywzNC43MDE4NTYgMzMuODE3OTkyLDM0LjE5MDIzMSAzMy40ODc1MzEsMzMuNjkxIGggLTQuMDU0Njg3IGMgMC4yNzQ4ODgsMC44MTY5ODUgMC42MTY0MDIsMS41NTU5OTYgMS4wMDk3NjUsMi4yMzQzNzUgbCAtMC4wMTE3MiwwLjAyMTQ4IGMgMC4wNDI1NCwwLjA3Njg0IDAuMDk5NDksMC4xNDg3NzggMC4xNDY0ODQsMC4yMjQ2MSAwLjI4MDAzMSwwLjQ1NDg3NiAwLjU4MTYwMiwwLjg4NjI2MiAwLjkxNzk2OSwxLjI3NTM5IDAuMjk5NTcxLDAuMzQ2NTYyIDAuNjIwNTkzLDAuNjY2NDM4IDAuOTY0ODQ0LDAuOTYwOTM4IDAuMTcxMjY2LDAuMTQ2NjIyIDAuMzQ2NjkyLDAuMjgzNzIgMC41MjUzOSwwLjQxMjEwOSAwLDAgMC4wMDIsMC4wMDIgMC4wMDIsMC4wMDIgMC4xNzc5ODksMC4xMjc3ODMgMC4zNTk1NywwLjI0NTc3NCAwLjU0NDkyMiwwLjM1NTQ2OSAwLjExNTA0NiwwLjA2ODA5IDAuMjMzNjgzLDAuMTI2Mzg0IDAuMzUxNTYzLDAuMTg3NSAwLjAxNTc3LDAuMDA4MiAwLjAzMTA2LDAuMDE3MzQgMC4wNDY4NywwLjAyNTM5IDAuMDU3MDEsMC4wMzEzNCAwLjExMzQ5NSwwLjA2NDA1IDAuMTcxODc1LDAuMDkxOCAwLjAwMTgsOC42OGUtNCAwLjAwNCwwLjAwMTEgMC4wMDU5LDAuMDAyIDAuMTkxODk2LDAuMDkwOTkgMC4zODY2NTEsMC4xNzMxMyAwLjU4NTkzNywwLjI0NjA5MyAwLjAwMjcsMTBlLTQgMC4wMDUxLDAuMDAyOSAwLjAwNzgsMC4wMDM5IDAsMCAwLjAwMiwwIDAuMDAyLDAgMC4xOTc3OSwwLjA3MjE3IDAuMzk4NTY0LDAuMTM0OTQ3IDAuNjAzNTE2LDAuMTg5NDUzIDAuMDA0LDAuMDAxMSAwLjAwNzcsMC4wMDI5IDAuMDExNzIsMC4wMDM5IDAsMCAwLjAwMiwwIDAuMDAyLDAgMC4yMDM5NywwLjA1MzgyIDAuNDEyMDAzLDAuMDk4NDIgMC42MjMwNDYsMC4xMzQ3NjYgMC4wMDUxLDguODJlLTQgMC4wMTA0OSwwLjAwMTEgMC4wMTU2MywwLjAwMiAwLjE4ODQ2NSwwLjAzMTg3IDAuMzgwMTA2LDAuMDU0MTYgMC41NzQyMTgsMC4wNzIyNyAwLjAwNDYsNC4zMmUtNCAwLjAwOSwwLjAwMTUgMC4wMTM2NywwLjAwMiAwLjAwNzEsMC4wMDE0IDAuMDE0MTcsMC4wMDMyIDAuMDIxNDgsMC4wMDM5IDAuMDEwOTMsMC4wMDE5IDAuMDIxOTcsMC4wMDI5IDAuMDMzMiwwLjAwMzkgMCwwIDAuMDAyLDAgMC4wMDIsMCAwLjAwNTMsNC40NmUtNCAwLjAxMDMxLDAuMDAxNSAwLjAxNTYzLDAuMDAyIDAsMCAwLjAwMiwwIDAuMDAyLDAgMC4xMTY5MzYsMC4wMDk2IDAuMjM4MDc0LDAuMDA5MSAwLjM1NzQyMiwwLjAxMzY3IDAuMDI0NzksOS41NWUtNCAwLjA0OTM0LDAuMDAzMiAwLjA3NDIyLDAuMDAzOSAwLjAxNTYsOC40NGUtNCAwLjAzMTEzLDAuMDAxNiAwLjA0Njg3LDAuMDAyIDAuMDYwMjYsMC4wMDM2IDAuMTIwMjcyLDAuMDA3NyAwLjE4MTY0MSwwLjAwNzggMC4wMDc5LDIuMmUtNSAwLjAxNTUsMCAwLjAyMzQ0LDAgMC4xNzgyNDQsMCAwLjM0ODAyLC0wLjAxNjk0IDAuNTIxNDg0LC0wLjAyNzM0IHYgLTAuMDA5OCBjIDAuMTg2NjA2LC0wLjAxMzQxIDAuMzc4MjYzLC0wLjAxNTUgMC41NjA1NDcsLTAuMDM5MDYgMC4wMjU1OSwtMC4wMDM1IDAuMDUwNjksLTAuMDA3OSAwLjA3NjE3LC0wLjAxMTcyIDAuMzQyMjU3LC0wLjA0NzY5IDAuNjczOCwtMC4xMTk4MTIgMC45OTYwOTQsLTAuMjEwOTM3IDEuNTAyNDksLTAuNDI0ODE3IDIuNzkzMTQ5LC0xLjMxMDE1NyAzLjg2MTMyOCwtMi42Nzk2ODggMS41NDksLTEuOTg2IDIuMzI0MjE4LC00LjQzNDY1NiAyLjMyNDIxOCwtNy4zNDc2NTYgMCwtMi4zNTYgLTAuNTMwODQzLC00LjQwNzI5NyAtMS41ODk4NDMsLTYuMTU0Mjk3IC0wLjgwNDI0NSwtMS4zMjY3MzggLTEuODk4ODgxLC0yLjMzOTQwNSAtMy4yODMyMDMsLTMuMDQxMDE1IC0wLjA0Mjg5LC0wLjAyMTc1IC0wLjA4OTQxLC0wLjAzOTM5IC0wLjEzMjgxMywtMC4wNjA1NSAtMC4xNzg4MjgsLTAuMDg3IC0wLjM1ODYwNiwtMC4xNzMxNyAtMC41NDY4NzUsLTAuMjUgLTAuMjMzNDg3LC0wLjA5NTc1IC0wLjQ3Mzg1NCwtMC4xODM3OTEgLTAuNzIyNjU2LC0wLjI2MzY3MiAyLjMyNDc2MywtNC4wMjU1MjIgNC42OTAyOTEsLTguMDI3NzU3IDYuOTc4NTE1LC0xMi4wNzQyMTkgSCAzMy44MDU4OTEgYyAtMy42MjQyOTksMCAtNC4zNTI4MDksMC42MTc2NDQ5IC01LjYxMTMyOSw0Ljg5NjQ4NSBMIDIzLjg3NjIwMywyNy41ODU1MzEgMTguMTE2NDM4LDguMDA1NDUzIGggLTQuMTY3OTY5IGwgMC45NTMxMjUsMy4xOTkyMTkgYyAwLjc5NDAwNCwyLjY2NDMwNiAwLjcyMzQ5NiwzLjk3MjIyIC0wLjAyMTQ4LDYuNDk0MTQgTCAxMS45NjAxODgsMjcuNTg1NTMxIDYuMjAyMzc0OSw4LjAwNTQ1MyBaIiBpZD0icGF0aDE1OTkiIC8+CiAgPHBhdGggaWQ9InBhdGg2IiBkPSJtIDY2LjkyLDguMDA1OTk5OSBjIC0wLjgxOSwwIC0xLjU1NCwwLjI5NSAtMi4xMTEsMC44NjEgLTAuNTkxLDAuNiAtMC45MiwxLjM3NjAwMDEgLTAuOTIsMi4xNzgwMDAxIDAsMC44MDIgMC4zMTMsMS41NDUgMC44ODcsMi4xMjggMC41ODMsMC41OTEgMS4zMzQsMC45MTIgMi4xNDUsMC45MTIgMC43OTMsMCAxLjU2MiwtMC4zMjEgMi4xNjEsLTAuOTAzIDAuNTc0LC0wLjU1NyAwLjg4NiwtMS4zMDEgMC44ODYsLTIuMTM3IDAsLTAuODExIC0wLjMyMSwtMS41NzAwMDAxIC0wLjg3OCwtMi4xMzYwMDAxIC0wLjU4MywtMC41OTEgLTEuMzQzLC0wLjkwMyAtMi4xNywtMC45MDMgeiBNIDY5LjU2MywxMS4wNzEgYyAwLDAuNzAxIC0wLjI3MSwxLjM1MSAtMC43NjksMS44MzIgLTAuNTIzLDAuNTA3IC0xLjE3MywwLjc3NyAtMS44OTEsMC43NzcgLTAuNjc1LDAgLTEuMzQyLC0wLjI3OCAtMS44NCwtMC43ODUgLTAuNDk4LC0wLjUwNiAtMC43NzcsLTEuMTU3IC0wLjc3NywtMS44NDkgMCwtMC42OTIgMC4yODcsLTEuMzY4MDAwMSAwLjgwMiwtMS44OTEwMDAxIDAuNDgxLC0wLjQ5IDEuMTMxLC0wLjc1MSAxLjg0LC0wLjc1MSAwLjcyNiwwIDEuMzc2LDAuMjcxIDEuODgzLDAuNzg1IDAuNDksMC40ODkgMC43NTIsMS4xNDgwMDAxIDAuNzUyLDEuODgyMDAwMSB6IE0gNjcuMDA1LDkuMjYzOTk5OSBoIC0xLjMgViAxMi43MDkgaCAwLjY1IFYgMTEuMjQgaCAwLjY0MiBsIDAuNzAxLDEuNDY5IGggMC43MjYgbCAtMC43NjksLTEuNTcxIGMgMC40OTgsLTAuMTAxIDAuNzg1LC0wLjQzOSAwLjc4NSwtMC45MjggMCwtMC42MjUwMDAxIC0wLjQ3MywtMC45NDYwMDAxIC0xLjQzNSwtMC45NDYwMDAxIHogbSAtMC4xMTksMC40MjIgYyAwLjYwOCwwIDAuODg2LDAuMTY5IDAuODg2LDAuNTkxMDAwMSAwLDAuNDA1IC0wLjI3OCwwLjU0OSAtMC44NywwLjU0OSBIIDY2LjM1MyBWIDkuNjg1OTk5OSBaIiAvPgogIDxwYXRoIGlkPSJwYXRoOCIgZD0ibSA2MS44MDcsNy44MjQ5OTk5IDAuMzM4LDIuMDUzNSBDIDYyLjQ2MDQ5NywxMS43OTUyODMgNjIuMTM5NiwxMi41ODkxNTMgNjEuMjg3NSwxNC4yMTk1IEwgNjAuMDkyLDE2LjUwNyBjIDAsMCAtMC45MTgsLTEuOTQxIC0yLjQ0MywtMy4wMTUgLTEuMjg1LC0wLjkwNSAtMi4xMjIsLTEuMTAyIC0zLjQzMSwtMC44MzIgLTEuNjgxLDAuMzQ3IC0zLjU4NywyLjM1NyAtNC40MTksNC44MzUgLTAuOTk1LDIuOTY1IC0xLjAwNSw0LjQgLTEuMDQsNS43MTggLTAuMDU2LDIuMTEzIDAuMjc3LDMuMzYyIDAuMjc3LDMuMzYyIDAsMCAtMS40NTEsLTIuNjg2IC0xLjQzOCwtNi42MiAwLjAwOSwtMi44MDggMC40NTEsLTUuMzU0IDEuNzUsLTcuODY3IDEuMTQzLC0yLjIwOTAwMDEgMi44NDIsLTMuNTM1MDAwMSA0LjM1LC0zLjY5MTAwMDEgMS41NTksLTAuMTYxIDIuNzkxLDAuNTkgMy43NDMsMS40MDQgQyA1OC40NCwxMC42NTUgNTkuNDUxLDEyLjUyMSA1OS40NTEsMTIuNTIxIFoiIC8+CiAgPHBhdGggaWQ9InBhdGgxMCIgZD0ibSA2Mi4xMDIsMzEuMDYzIGMgMCwwIC0xLjA1NywxLjg4OSAtMS43MTUsMi42MTcgLTAuNjU5LDAuNzI4IC0xLjgzNywyLjAxIC0zLjI5MiwyLjY1MSAtMS40NTYsMC42NDEgLTIuMjE4LDAuNzYyIC0zLjY1NiwwLjYyNCAtMS40MzcsLTAuMTM4IC0yLjc3MywtMC45NyAtMy4yNDEsLTEuMzE3IC0wLjQ2OCwtMC4zNDcgLTEuNjY0LC0xLjM2OSAtMi4zMzksLTIuMzIyIC0wLjY3NiwtMC45NTQgLTEuNzMzLC0yLjg1OSAtMS43MzMsLTIuODU5IDAsMCAwLjU4OSwxLjkxMSAwLjk1OCwyLjcyMSAwLjIxMiwwLjQ2NiAwLjg2NCwxLjg5NCAxLjc5LDMuMTM2IDAuODYyLDEuMTU5IDIuNTM5LDMuMTU0IDUuMDg2LDMuNjA0IDIuNTQ3LDAuNDUxIDQuMjk3LC0wLjY5MyA0LjczLC0wLjk3MSAwLjQzMywtMC4yNzcgMS40MzIzMDksLTAuOTMwNDIgMi4wMTAyNDMsLTEuNTQ4NDgyIDAuNjAzMDY2LC0wLjY0NDkzOCAwLjkyMzA4MywtMS4xMDczOTMgMS4zMjUxMTEsLTEuOTIwNzc1IDAuMjkyMDU3LC0wLjU5MDg4OSAwLjU0NDc2MywtMS45NzczMDQgMC4zODExNDYsLTIuODI5MjQzIHoiIC8+Cjwvc3ZnPgo="
    And expected attachment for vp flow is "data:image/png;base64,iVBORw0KGgokJg"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile    | credentialType             | verifierProfile                | presentationDefinitionID                  | fields         | proofType | credentialEncoded                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
      | bank_issuer/v1.0 | UniversityDegreeCredential | v_myprofile_jwt_no_strict/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | jwt       | ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsCiAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiLAogICAgImh0dHBzOi8vdzNpZC5vcmcvdmMvc3RhdHVzLWxpc3QvMjAyMS92MSIKICBdLAogICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgImlkIjogInVybjp1dWlkOjViYjIwNTU4LTI1Y2UtNDBiNS04MGZjLThhZjY5MWVlZGNjZSIsCiAgICAic3RhdHVzTGlzdENyZWRlbnRpYWwiOiAiaHR0cDovL3ZjLXJlc3QtZWNoby50cnVzdGJsb2MubG9jYWw6ODA3NS9pc3N1ZXIvZ3JvdXBzL2dyb3VwX2FjbWVfaXNzdWVyL2NyZWRlbnRpYWxzL3N0YXR1cy8wNmIxM2U5Mi0yN2E2LTRiNzYtOTk3Ny02ZWNlMjA3NzgzZGQiLAogICAgInN0YXR1c0xpc3RJbmRleCI6ICI2NTQ4IiwKICAgICJzdGF0dXNQdXJwb3NlIjogInJldm9jYXRpb24iLAogICAgInR5cGUiOiAiU3RhdHVzTGlzdDIwMjFFbnRyeSIKICB9LAogICJjcmVkZW50aWFsU3ViamVjdCI6IHsKICAgICJkZWdyZWUiOiB7CiAgICAgICJkZWdyZWUiOiAiTUlUIiwKICAgICAgInR5cGUiOiAiQmFjaGVsb3JEZWdyZWUiCiAgICB9LAogICAgInBob3RvIjogewogICAgICAiaWQiOiAiZG9jNDQ1IiwKICAgICAgInR5cGUiOiBbCiAgICAgICAgIkVtYmVkZGVkQXR0YWNobWVudCIKICAgICAgXSwKICAgICAgIm1pbWVUeXBlIjogImltYWdlL3BuZyIsCiAgICAgICJ1cmkiOiAiZGF0YTppbWFnZS9wbmc7YmFzZTY0LGlWQk9SdzBLR2dva0pnIiwKICAgICAgImRlc2NyaXB0aW9uIjogImIiCiAgICB9LAogICAgInJlbW90ZSI6IHsKICAgICAgImlkIjogInJlbW90ZV9kb2MiLAogICAgICAidHlwZSI6IFsKICAgICAgICAiUmVtb3RlQXR0YWNobWVudCIKICAgICAgXSwKICAgICAgIm1pbWVUeXBlIjogImltYWdlL3N2ZyIsCiAgICAgICJ1cmkiOiAiaHR0cHM6Ly93d3cudzMub3JnL2Fzc2V0cy9sb2dvcy93M2MvdzNjLW5vLWJhcnMuc3ZnIiwKICAgICAgImRlc2NyaXB0aW9uIjogImEiLAogICAgICAiaGFzaC1hbGciIDogIlNIQS0yNTYiLAogICAgICAiaGFzaCIgOiAiNzk2NjYzYzM1YTEzZWJkZTAwZDk5ZDQxNDliYjBiMTEyNGUzOTFmZmY5OWU4ZjU1ZTg5MDhkNGM4YjE1ZmI2ZCIKICAgIH0sCiAgICAiaWQiOiAiZGlkOmlvbjpFaUJ5UUF4WG1PQUVNN1RsRVVHOXU2UnIycnM1UUNMeHVPZlZsTk41elQzUm1ROmV5SmtaV3gwWVNJNmV5SndZWFJqYUdWeklqcGJleUpoWTNScGIyNGlPaUpoWkdRdGNIVmliR2xqTFd0bGVYTWlMQ0p3ZFdKc2FXTkxaWGx6SWpwYmV5SnBaQ0k2SWw5dVZUbHlia0ZwY0hnM01GaFhTRFJLZFVwM1QxVnBXalo0U1VaTllURm5SbWhLVVZVd1ZIWjJNMUVpTENKd2RXSnNhV05MWlhsS2Qyc2lPbnNpWTNKMklqb2lVQzB6T0RRaUxDSnJhV1FpT2lKZmJsVTVjbTVCYVhCNE56QllWMGcwU25WS2QwOVZhVm8yZUVsR1RXRXhaMFpvU2xGVk1GUjJkak5SSWl3aWEzUjVJam9pUlVNaUxDSjRJam9pTmxjM2RIRmFNWFpsVFRkWlNFNTVkRE4wT1hoTU9UZE1UMGh6WnpreWJtNXdYMlJzYVdOUWNWUmxjalJ0U1hoWmVUVnhNMDUyZVVrd2N6STFXa2xGT0NJc0lua2lPaUpEYTFSWFppMVlWVnA2TFZkMk56SXROWEJ2T1dkcGNuWjZTbmQ0TW5GVFEwa3labUY1YkhkWGNtdHRhbnBYTXpGRWNXRkhjalpGV2tRdGRWbERVMmRPSW4wc0luQjFjbkJ2YzJWeklqcGJJbUYxZEdobGJuUnBZMkYwYVc5dUlpd2lZWE56WlhKMGFXOXVUV1YwYUc5a0lsMHNJblI1Y0dVaU9pSktjMjl1VjJWaVMyVjVNakF5TUNKOVhYMWRMQ0oxY0dSaGRHVkRiMjF0YVhSdFpXNTBJam9pUldsRE1taHRjMlJGTkhGT2QyMVRRMUJtTWpGMU1FeDZRa2h2YzNCV1VGRnNPVkp0VEdzM05GWjFaelZyZHlKOUxDSnpkV1ptYVhoRVlYUmhJanA3SW1SbGJIUmhTR0Z6YUNJNklrVnBRUzFaT1hWMFRVNWhhVWhWUjFwdE5UQm1RVkpqY1ZOYWNVZEJNemQ2UWxaVU5VWTRTMGx0WHpOVGRrRWlMQ0p5WldOdmRtVnllVU52YlcxcGRHMWxiblFpT2lKRmFVSlJiVU5pZGw5VlF6VlJSa04yT1VOd2IxSlBhVk01YkhaQ2RuZHVZMmxaTFY5NGNsRTRTVEp2UjBKbkluMHNJblI1Y0dVaU9pSmpjbVZoZEdVaWZRIiwKICAgICJuYW1lIjogIkpheWRlbiBEb2UiLAogICAgInNwb3VzZSI6ICJkaWQ6ZXhhbXBsZTpjMjc2ZTEyZWMyMWViZmViMWY3MTJlYmM2ZjEiCiAgfSwKICAiZXhwaXJhdGlvbkRhdGUiOiAiMjAyNS0wMy0xOFQyMjowNjozMS4zNDI1MDEwNloiLAogICJpZCI6ICJ1cm46dXVpZDo3Y2JiOWJhMi0zODAxLTQ3ODYtYjdjMS1hZDJkNDI5MjQzYTgiLAogICJpc3N1YW5jZURhdGUiOiAiMjAyNC0wMy0xOFQyMjowNjozMS4zNzU0MzQxMzFaIiwKICAiaXNzdWVyIjogewogICAgImlkIjogImRpZDppb246RWlBb2FISllGMlE2azl6aXloNFBEcnVzSVp0TlVLbTEtYUZyQXZyUERDRU1TUTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKaFpHUXRjSFZpYkdsakxXdGxlWE1pTENKd2RXSnNhV05MWlhseklqcGJleUpwWkNJNkltTTFOR1EwTWpnMkxXSXlOak10TkRJM01DMWhNRE14TFRVeU9USmlZelJqTmpSalpDSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmxJam9pUVZGQlFpSXNJbXRwWkNJNkltTTFOR1EwTWpnMkxXSXlOak10TkRJM01DMWhNRE14TFRVeU9USmlZelJqTmpSalpDSXNJbXQwZVNJNklsSlRRU0lzSW00aU9pSnVXVEJpTm1GR1RFNVZhbVEzZUVGcGJWcDRkVWd3Wms1U1RVY3paV05IV0c5WlMzUlJXRFIxUzFGamMxbFpVMjVHYUVGRGVEaG1hbkJuTmpKSmVWcENkVlJRWVRadVozTjJYMDVSUWtoVVdVbE1SakpSV1ZWUWFUUlFWRXN0ZVVFM1RtUlBTbFp3TlVGRlZ6VnljM2xzWlRnd1N5MVBVR2xVVVcxS1IyeDVVamhKVWtaSU5rOXRNM00yWVhOdFdWbDVaa2t0TFd0UlpUaElhMGQwYlhjM1RHbGlWV1ZaV25kM1J6bElTV3g2U0RSUU5taElUM05VWmxoaFJGbDJiRFUzV1dwMWJtZ3ljVlV5WVdsWFJGazVRV2xVVWtKcGJVeENhRWx1Wm5ZME5VNVllVGwxZDNKR09YTlpiRmh1YkdkNWJWVlRNVkZXY1RjNVZTMWxia3RtUlhNelIyczJSVVJpVjNKSGJYcEhjSFJQWkdwemRFa3dPV1Y0YVZSSU9FdHJkbmhPUldoUWVreGtlbmt3VUZObFJXWjRYMmxUV1d4TVpGbEpSa1ZVTjJveE1VNXZMVEZ5TWtWNlFrTnBVVFZ1ZEZJeE0xRWlmU3dpY0hWeWNHOXpaWE1pT2xzaVlYVjBhR1Z1ZEdsallYUnBiMjRpTENKaGMzTmxjblJwYjI1TlpYUm9iMlFpWFN3aWRIbHdaU0k2SWtwemIyNVhaV0pMWlhreU1ESXdJbjFkZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVU5FUmxGUVpuaFNSbk5zY2tGSWJWbzRhWE5RYkU0NFF6WktVbVJ6ZW5RMFpuSTBhRGxJTkdSbU1WWm5JbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsQlNETXhORmRxUlROQmFUUmhMWE15U205SGNYWmpTMVZwVEVSZk1USlZaM1Z4WTBZMWJVZHpSblowWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUVMxcGRrWnFUVFpMZG14MllVdFVPR2RDYTNCSmF6Wkxaa3h2T1VsNU1HbzBZV2htYWkxclQwbDJXbEVpZlN3aWRIbHdaU0k2SW1OeVpXRjBaU0o5IiwKICAgICJuYW1lIjogIkFjbWUgSXNzdWVyIgogIH0sCiAgInR5cGUiOiBbCiAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLAogICAgIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIgogIF0KfQ== |

  @oidc4vc_rest_pre_auth_flow_compose_with_attachment_evidence
  Scenario Outline: OIDC credential issuance and verification Pre Auth flow
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "<credentialType>" with templateID ""
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And proofType is "<proofType>"
    And initiateIssuanceVersion is "2"
    And credentialCompose is active with "<credentialEncoded>"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then "1" credentials are issued
    Then wallet add attachments to vp flow with data '<attachmentData>'
    And expected attachment for vp flow is "data:text/plain;base64,aGVsbG8="
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile    | credentialType             | attachmentData                                         | verifierProfile                | presentationDefinitionID                  | fields         | proofType | credentialEncoded                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
      | bank_issuer/v1.0 | UniversityDegreeCredential | { "evidence_doc" : "data:text/plain;base64,aGVsbG8=" } | v_myprofile_jwt_no_strict/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | jwt       | ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsCiAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiLAogICAgImh0dHBzOi8vdzNpZC5vcmcvdmMvc3RhdHVzLWxpc3QvMjAyMS92MSIKICBdLAogICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgImlkIjogInVybjp1dWlkOjViYjIwNTU4LTI1Y2UtNDBiNS04MGZjLThhZjY5MWVlZGNjZSIsCiAgICAic3RhdHVzTGlzdENyZWRlbnRpYWwiOiAiaHR0cDovL3ZjLXJlc3QtZWNoby50cnVzdGJsb2MubG9jYWw6ODA3NS9pc3N1ZXIvZ3JvdXBzL2dyb3VwX2FjbWVfaXNzdWVyL2NyZWRlbnRpYWxzL3N0YXR1cy8wNmIxM2U5Mi0yN2E2LTRiNzYtOTk3Ny02ZWNlMjA3NzgzZGQiLAogICAgInN0YXR1c0xpc3RJbmRleCI6ICI2NTQ4IiwKICAgICJzdGF0dXNQdXJwb3NlIjogInJldm9jYXRpb24iLAogICAgInR5cGUiOiAiU3RhdHVzTGlzdDIwMjFFbnRyeSIKICB9LAogICJjcmVkZW50aWFsU3ViamVjdCI6IHsKICAgICJkZWdyZWUiOiB7CiAgICAgICJkZWdyZWUiOiAiTUlUIiwKICAgICAgInR5cGUiOiAiQmFjaGVsb3JEZWdyZWUiCiAgICB9LAogICAgImV2aWRlbmNlIjogewogICAgICAiaWQiOiAiZXZpZGVuY2VfZG9jIiwKICAgICAgInR5cGUiOiBbCiAgICAgICAgIkF0dGFjaG1lbnRFdmlkZW5jZSIKICAgICAgXSwKICAgICAgImhhc2giIDogIjJjZjI0ZGJhNWZiMGEzMGUyNmU4M2IyYWM1YjllMjllMWIxNjFlNWMxZmE3NDI1ZTczMDQzMzYyOTM4Yjk4MjQiLAogICAgICAiaGFzaC1hbGciIDogIlNIQS0yNTYiLAogICAgICAibWltZVR5cGUiOiAidGV4dC9wbGFpbiIKICAgIH0sCiAgICAiaWQiOiAiZGlkOmlvbjpFaUJ5UUF4WG1PQUVNN1RsRVVHOXU2UnIycnM1UUNMeHVPZlZsTk41elQzUm1ROmV5SmtaV3gwWVNJNmV5SndZWFJqYUdWeklqcGJleUpoWTNScGIyNGlPaUpoWkdRdGNIVmliR2xqTFd0bGVYTWlMQ0p3ZFdKc2FXTkxaWGx6SWpwYmV5SnBaQ0k2SWw5dVZUbHlia0ZwY0hnM01GaFhTRFJLZFVwM1QxVnBXalo0U1VaTllURm5SbWhLVVZVd1ZIWjJNMUVpTENKd2RXSnNhV05MWlhsS2Qyc2lPbnNpWTNKMklqb2lVQzB6T0RRaUxDSnJhV1FpT2lKZmJsVTVjbTVCYVhCNE56QllWMGcwU25WS2QwOVZhVm8yZUVsR1RXRXhaMFpvU2xGVk1GUjJkak5SSWl3aWEzUjVJam9pUlVNaUxDSjRJam9pTmxjM2RIRmFNWFpsVFRkWlNFNTVkRE4wT1hoTU9UZE1UMGh6WnpreWJtNXdYMlJzYVdOUWNWUmxjalJ0U1hoWmVUVnhNMDUyZVVrd2N6STFXa2xGT0NJc0lua2lPaUpEYTFSWFppMVlWVnA2TFZkMk56SXROWEJ2T1dkcGNuWjZTbmQ0TW5GVFEwa3labUY1YkhkWGNtdHRhbnBYTXpGRWNXRkhjalpGV2tRdGRWbERVMmRPSW4wc0luQjFjbkJ2YzJWeklqcGJJbUYxZEdobGJuUnBZMkYwYVc5dUlpd2lZWE56WlhKMGFXOXVUV1YwYUc5a0lsMHNJblI1Y0dVaU9pSktjMjl1VjJWaVMyVjVNakF5TUNKOVhYMWRMQ0oxY0dSaGRHVkRiMjF0YVhSdFpXNTBJam9pUldsRE1taHRjMlJGTkhGT2QyMVRRMUJtTWpGMU1FeDZRa2h2YzNCV1VGRnNPVkp0VEdzM05GWjFaelZyZHlKOUxDSnpkV1ptYVhoRVlYUmhJanA3SW1SbGJIUmhTR0Z6YUNJNklrVnBRUzFaT1hWMFRVNWhhVWhWUjFwdE5UQm1RVkpqY1ZOYWNVZEJNemQ2UWxaVU5VWTRTMGx0WHpOVGRrRWlMQ0p5WldOdmRtVnllVU52YlcxcGRHMWxiblFpT2lKRmFVSlJiVU5pZGw5VlF6VlJSa04yT1VOd2IxSlBhVk01YkhaQ2RuZHVZMmxaTFY5NGNsRTRTVEp2UjBKbkluMHNJblI1Y0dVaU9pSmpjbVZoZEdVaWZRIiwKICAgICJuYW1lIjogIkpheWRlbiBEb2UiLAogICAgInNwb3VzZSI6ICJkaWQ6ZXhhbXBsZTpjMjc2ZTEyZWMyMWViZmViMWY3MTJlYmM2ZjEiCiAgfSwKICAiZXhwaXJhdGlvbkRhdGUiOiAiMjAyNS0wMy0xOFQyMjowNjozMS4zNDI1MDEwNloiLAogICJpZCI6ICJ1cm46dXVpZDo3Y2JiOWJhMi0zODAxLTQ3ODYtYjdjMS1hZDJkNDI5MjQzYTgiLAogICJpc3N1YW5jZURhdGUiOiAiMjAyNC0wMy0xOFQyMjowNjozMS4zNzU0MzQxMzFaIiwKICAiaXNzdWVyIjogewogICAgImlkIjogImRpZDppb246RWlBb2FISllGMlE2azl6aXloNFBEcnVzSVp0TlVLbTEtYUZyQXZyUERDRU1TUTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKaFpHUXRjSFZpYkdsakxXdGxlWE1pTENKd2RXSnNhV05MWlhseklqcGJleUpwWkNJNkltTTFOR1EwTWpnMkxXSXlOak10TkRJM01DMWhNRE14TFRVeU9USmlZelJqTmpSalpDSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmxJam9pUVZGQlFpSXNJbXRwWkNJNkltTTFOR1EwTWpnMkxXSXlOak10TkRJM01DMWhNRE14TFRVeU9USmlZelJqTmpSalpDSXNJbXQwZVNJNklsSlRRU0lzSW00aU9pSnVXVEJpTm1GR1RFNVZhbVEzZUVGcGJWcDRkVWd3Wms1U1RVY3paV05IV0c5WlMzUlJXRFIxUzFGamMxbFpVMjVHYUVGRGVEaG1hbkJuTmpKSmVWcENkVlJRWVRadVozTjJYMDVSUWtoVVdVbE1SakpSV1ZWUWFUUlFWRXN0ZVVFM1RtUlBTbFp3TlVGRlZ6VnljM2xzWlRnd1N5MVBVR2xVVVcxS1IyeDVVamhKVWtaSU5rOXRNM00yWVhOdFdWbDVaa2t0TFd0UlpUaElhMGQwYlhjM1RHbGlWV1ZaV25kM1J6bElTV3g2U0RSUU5taElUM05VWmxoaFJGbDJiRFUzV1dwMWJtZ3ljVlV5WVdsWFJGazVRV2xVVWtKcGJVeENhRWx1Wm5ZME5VNVllVGwxZDNKR09YTlpiRmh1YkdkNWJWVlRNVkZXY1RjNVZTMWxia3RtUlhNelIyczJSVVJpVjNKSGJYcEhjSFJQWkdwemRFa3dPV1Y0YVZSSU9FdHJkbmhPUldoUWVreGtlbmt3VUZObFJXWjRYMmxUV1d4TVpGbEpSa1ZVTjJveE1VNXZMVEZ5TWtWNlFrTnBVVFZ1ZEZJeE0xRWlmU3dpY0hWeWNHOXpaWE1pT2xzaVlYVjBhR1Z1ZEdsallYUnBiMjRpTENKaGMzTmxjblJwYjI1TlpYUm9iMlFpWFN3aWRIbHdaU0k2SWtwemIyNVhaV0pMWlhreU1ESXdJbjFkZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVU5FUmxGUVpuaFNSbk5zY2tGSWJWbzRhWE5RYkU0NFF6WktVbVJ6ZW5RMFpuSTBhRGxJTkdSbU1WWm5JbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsQlNETXhORmRxUlROQmFUUmhMWE15U205SGNYWmpTMVZwVEVSZk1USlZaM1Z4WTBZMWJVZHpSblowWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUVMxcGRrWnFUVFpMZG14MllVdFVPR2RDYTNCSmF6Wkxaa3h2T1VsNU1HbzBZV2htYWkxclQwbDJXbEVpZlN3aWRIbHdaU0k2SW1OeVpXRjBaU0o5IiwKICAgICJuYW1lIjogIkFjbWUgSXNzdWVyIgogIH0sCiAgInR5cGUiOiBbCiAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLAogICAgIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIgogIF0KfQ== |

  @oidc4vc_rest_pre_auth_flow_trustlist_success
  Scenario Outline: OIDC credential issuance and verification Pre Auth flow with trustlist (Success)
    Given Profile "<issuerProfile>" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "<credentialType>" with templateID "<credentialTemplate>"
    And Profile "<verifierProfile>" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then "1" credentials are issued
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
    Then "1" credentials are issued
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
    Then "1" credentials are issued
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

  @oidc4vc_rest_preauth_schema_invalid_field_in_pd
  Scenario: OIDC credential issuance and verification Pre Auth flow (Invalid Field in Presentation Definition)
    Given Profile "i_myprofile_ud_es256k_jwt/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "CrudeProductCredential" with templateID "crudeProductCredentialTemplateID"
    And Profile "v_myprofile_jwt/v1.0" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate credential issuance using pre authorization code flow
    Then "1" credentials are issued
    And User interacts with Verifier and initiate OIDC4VP interaction under "v_myprofile_jwt/v1.0" profile with presentation definition ID "32f54163-no-limit-disclosure-optional-fields" and fields "lpr_category_id,commuter_classification,invalidfield" and receives "field invalidfield not found" error

  @oidc4vc_auth_malicious_attacker_steals_signingKeyID
  Scenario: OIDC credential issuance and verification Auth flow (Malicious attacker stealing auth code & calling token endpoint with it)
    Given Profile "bank_issuer/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "UniversityDegreeCredential" with templateID "universityDegreeTemplateID"
    Then Malicious attacker stealing auth code from User and using "malicious_attacker_id" ClientID makes /token request and receives "invalid_client" error

  @oidc4vc_auth_malicious_attacker_changed_signingKeyID
  Scenario: OIDC credential issuance and verification Auth flow (Malicious attacker changed signingKeyID & calling credential endpoint with it)
    Given Profile "bank_issuer/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "UniversityDegreeCredential" with templateID "universityDegreeTemplateID"
    Then Malicious attacker changed JWT kid header and makes /credential request and receives "invalid_or_missing_proof" error

  @oidc4vc_auth_malicious_attacker_changed_jwt
  Scenario: OIDC credential issuance and verification Auth flow (Malicious attacker changed JWT signature value & calling credential endpoint with it)
    Given Profile "bank_issuer/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And   User holds credential "UniversityDegreeCredential" with templateID "universityDegreeTemplateID"
    Then Malicious attacker changed signature value and makes /credential request and receives "invalid_or_missing_proof" error

  @oidc4vc_auth_malicious_attacker_changed_nonce
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
    Then "1" credentials are issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>"
    And Verifier waits for "verifier.oidc-interaction-succeeded.v1" event
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
    Then "1" credentials are issued
    And User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>" and receives "no matching credentials found" error
    And Verifier waits for "verifier.oidc-interaction-no-match-found.v1" event
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
    Then "1" credentials are issued
    And wallet configured to use hardcoded vp_token format "jwt" for OIDC4VP interaction
    And User interacts with Verifier and initiate OIDC4VP interaction under "<verifierProfile>" profile with presentation definition ID "<presentationDefinitionID>" and fields "<fields>" and receives "no matching credentials found" error
    And Verifier waits for "verifier.oidc-interaction-no-match-found.v1" event
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
    Then "1" credentials are issued
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
    Then "1" credentials are issued
    Then User interacts with Verifier and initiate OIDC4VP interaction under "v_myprofile_jwt_client_attestation/v1.0" profile with presentation definition ID "attestation-vc-single-field" and fields "degree_type_id"
    And Verifier with profile "v_myprofile_jwt_client_attestation/v1.0" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "v_myprofile_jwt_client_attestation/v1.0" requests deleted interactions claims

  @oidc4vc_rest_multi_vp
  Scenario: OIDC credential pre-authorized code flow issuance and verification with multiple VPs
    Given Profile "bank_issuer/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And  User holds credential "UniversityDegreeCredential,VerifiedEmployee" with templateID "nil"
    And  User wants to make credentials request based on credential offer "false"
    And Profile "v_myprofile_multivp_jwt/v1.0" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"

    When User interacts with Wallet to initiate batch credential issuance using pre authorization code flow
    Then "2" credentials are issued
    Then expected credential count for vp flow is "2"
    Then User interacts with Verifier and initiate OIDC4VP interaction under "v_myprofile_multivp_jwt/v1.0" profile with presentation definition ID "8bc45260-ed00-4c23-a32a-b70e5aef3d92" and fields "degree_type_id,verified_employee_id" using multi vps
    And Verifier with profile "v_myprofile_multivp_jwt/v1.0" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "v_myprofile_multivp_jwt/v1.0" requests deleted interactions claims
