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
      | issuerProfile    | credentialType                                                     | useCredentialOfferForCredentialRequest | issuedCredentialsAmount | verifierProfile      | presentationDefinitionID                  | fields         |  expectedCredentialCountVPFlow |
#      SDJWT issuer, JWT verifier, no limit disclosure in PD query.
      | bank_issuer/v1.0 | UniversityDegreeCredential,CrudeProductCredential,VerifiedEmployee | false                                  | 3                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | 1                              |
      | bank_issuer/v1.0 | UniversityDegreeCredential,CrudeProductCredential                  | false                                  | 2                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | 1                              |
#     Same VC type
      | bank_issuer/v1.0 | UniversityDegreeCredential,UniversityDegreeCredential              | false                                  | 2                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | 2                              |
      | bank_issuer/v1.0 | UniversityDegreeCredential,UniversityDegreeCredential              | true                                   | 2                       | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | 2                              |

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
    And expected attachment for vp flow is "a"
    And expected attachment for vp flow is "b"
    And Verifier with profile "<verifierProfile>" retrieves interactions claims
    Then we wait 2 seconds
    And Verifier with profile "<verifierProfile>" requests deleted interactions claims

    Examples:
      | issuerProfile                | credentialType             | credentialTemplate | verifierProfile      | presentationDefinitionID                  | fields         | proofType | credentialEncoded                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
      | acme_issuer/v1.0             | UniversityDegreeCredential |                    | v_myprofile_jwt/v1.0 | 32f54163-no-limit-disclosure-single-field | degree_type_id | jwt       | ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsCiAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiLAogICAgImh0dHBzOi8vdzNpZC5vcmcvdmMvc3RhdHVzLWxpc3QvMjAyMS92MSIKICBdLAogICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgImlkIjogInVybjp1dWlkOjViYjIwNTU4LTI1Y2UtNDBiNS04MGZjLThhZjY5MWVlZGNjZSIsCiAgICAic3RhdHVzTGlzdENyZWRlbnRpYWwiOiAiaHR0cDovL3ZjLXJlc3QtZWNoby50cnVzdGJsb2MubG9jYWw6ODA3NS9pc3N1ZXIvZ3JvdXBzL2dyb3VwX2FjbWVfaXNzdWVyL2NyZWRlbnRpYWxzL3N0YXR1cy8wNmIxM2U5Mi0yN2E2LTRiNzYtOTk3Ny02ZWNlMjA3NzgzZGQiLAogICAgInN0YXR1c0xpc3RJbmRleCI6ICI2NTQ4IiwKICAgICJzdGF0dXNQdXJwb3NlIjogInJldm9jYXRpb24iLAogICAgInR5cGUiOiAiU3RhdHVzTGlzdDIwMjFFbnRyeSIKICB9LAogICJjcmVkZW50aWFsU3ViamVjdCI6IHsKICAgICJkZWdyZWUiOiB7CiAgICAgICJkZWdyZWUiOiAiTUlUIiwKICAgICAgInR5cGUiOiAiQmFjaGVsb3JEZWdyZWUiCiAgICB9LAogICAgInBob3RvIjogewogICAgICAiaWQiOiAiZG9jNDQ1IiwKICAgICAgInR5cGUiOiBbCiAgICAgICAgIkVtYmVkZGVkQXR0YWNobWVudCIKICAgICAgXSwKICAgICAgIm1pbWVUeXBlIjogImltYWdlL3BuZyIsCiAgICAgICJ1cmkiOiAiZGF0YTppbWFnZS9wbmc7YmFzZTY0LGlWQk9SdzBLR2dva0pnIiwKICAgICAgImRlc2NyaXB0aW9uIjogImIiCiAgICB9LAogICAgInJlbW90ZSI6IHsKICAgICAgImlkIjogInJlbW90ZV9kb2MiLAogICAgICAidHlwZSI6IFsKICAgICAgICAiUmVtb3RlQXR0YWNobWVudCIKICAgICAgXSwKICAgICAgIm1pbWVUeXBlIjogImltYWdlL3N2ZyIsCiAgICAgICJ1cmkiOiAiaHR0cHM6Ly93d3cudzMub3JnL2Fzc2V0cy9sb2dvcy93M2MvdzNjLW5vLWJhcnMuc3ZnIiwKICAgICAgImRlc2NyaXB0aW9uIjogImEiCiAgICB9LAogICAgImlkIjogImRpZDppb246RWlCeVFBeFhtT0FFTTdUbEVVRzl1NlJyMnJzNVFDTHh1T2ZWbE5ONXpUM1JtUTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKaFpHUXRjSFZpYkdsakxXdGxlWE1pTENKd2RXSnNhV05MWlhseklqcGJleUpwWkNJNklsOXVWVGx5YmtGcGNIZzNNRmhYU0RSS2RVcDNUMVZwV2paNFNVWk5ZVEZuUm1oS1VWVXdWSFoyTTFFaUxDSndkV0pzYVdOTFpYbEtkMnNpT25zaVkzSjJJam9pVUMwek9EUWlMQ0pyYVdRaU9pSmZibFU1Y201QmFYQjROekJZVjBnMFNuVktkMDlWYVZvMmVFbEdUV0V4WjBab1NsRlZNRlIyZGpOUklpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaU5sYzNkSEZhTVhabFRUZFpTRTU1ZEROME9YaE1PVGRNVDBoelp6a3libTV3WDJSc2FXTlFjVlJsY2pSdFNYaFplVFZ4TTA1MmVVa3djekkxV2tsRk9DSXNJbmtpT2lKRGExUlhaaTFZVlZwNkxWZDJOekl0TlhCdk9XZHBjblo2U25kNE1uRlRRMGt5Wm1GNWJIZFhjbXR0YW5wWE16RkVjV0ZIY2paRldrUXRkVmxEVTJkT0luMHNJbkIxY25CdmMyVnpJanBiSW1GMWRHaGxiblJwWTJGMGFXOXVJaXdpWVhOelpYSjBhVzl1VFdWMGFHOWtJbDBzSW5SNWNHVWlPaUpLYzI5dVYyVmlTMlY1TWpBeU1DSjlYWDFkTENKMWNHUmhkR1ZEYjIxdGFYUnRaVzUwSWpvaVJXbERNbWh0YzJSRk5IRk9kMjFUUTFCbU1qRjFNRXg2UWtodmMzQldVRkZzT1ZKdFRHczNORloxWnpWcmR5SjlMQ0p6ZFdabWFYaEVZWFJoSWpwN0ltUmxiSFJoU0dGemFDSTZJa1ZwUVMxWk9YVjBUVTVoYVVoVlIxcHROVEJtUVZKamNWTmFjVWRCTXpkNlFsWlVOVVk0UzBsdFh6TlRka0VpTENKeVpXTnZkbVZ5ZVVOdmJXMXBkRzFsYm5RaU9pSkZhVUpSYlVOaWRsOVZRelZSUmtOMk9VTndiMUpQYVZNNWJIWkNkbmR1WTJsWkxWOTRjbEU0U1RKdlIwSm5JbjBzSW5SNWNHVWlPaUpqY21WaGRHVWlmUSIsCiAgICAibmFtZSI6ICJKYXlkZW4gRG9lIiwKICAgICJzcG91c2UiOiAiZGlkOmV4YW1wbGU6YzI3NmUxMmVjMjFlYmZlYjFmNzEyZWJjNmYxIgogIH0sCiAgImV4cGlyYXRpb25EYXRlIjogIjIwMjUtMDMtMThUMjI6MDY6MzEuMzQyNTAxMDZaIiwKICAiaWQiOiAidXJuOnV1aWQ6N2NiYjliYTItMzgwMS00Nzg2LWI3YzEtYWQyZDQyOTI0M2E4IiwKICAiaXNzdWFuY2VEYXRlIjogIjIwMjQtMDMtMThUMjI6MDY6MzEuMzc1NDM0MTMxWiIsCiAgImlzc3VlciI6IHsKICAgICJpZCI6ICJkaWQ6aW9uOkVpQW9hSEpZRjJRNms5eml5aDRQRHJ1c0ladE5VS20xLWFGckF2clBEQ0VNU1E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSmhaR1F0Y0hWaWJHbGpMV3RsZVhNaUxDSndkV0pzYVdOTFpYbHpJanBiZXlKcFpDSTZJbU0xTkdRME1qZzJMV0l5TmpNdE5ESTNNQzFoTURNeExUVXlPVEppWXpSak5qUmpaQ0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpsSWpvaVFWRkJRaUlzSW10cFpDSTZJbU0xTkdRME1qZzJMV0l5TmpNdE5ESTNNQzFoTURNeExUVXlPVEppWXpSak5qUmpaQ0lzSW10MGVTSTZJbEpUUVNJc0ltNGlPaUp1V1RCaU5tRkdURTVWYW1RM2VFRnBiVnA0ZFVnd1prNVNUVWN6WldOSFdHOVpTM1JSV0RSMVMxRmpjMWxaVTI1R2FFRkRlRGhtYW5Cbk5qSkplVnBDZFZSUVlUWnVaM04yWDA1UlFraFVXVWxNUmpKUldWVlFhVFJRVkVzdGVVRTNUbVJQU2xad05VRkZWelZ5YzNsc1pUZ3dTeTFQVUdsVVVXMUtSMng1VWpoSlVrWklOazl0TTNNMllYTnRXVmw1WmtrdExXdFJaVGhJYTBkMGJYYzNUR2xpVldWWlduZDNSemxJU1d4NlNEUlFObWhJVDNOVVpsaGhSRmwyYkRVM1dXcDFibWd5Y1ZVeVlXbFhSRms1UVdsVVVrSnBiVXhDYUVsdVpuWTBOVTVZZVRsMWQzSkdPWE5aYkZodWJHZDViVlZUTVZGV2NUYzVWUzFsYmt0bVJYTXpSMnMyUlVSaVYzSkhiWHBIY0hSUFpHcHpkRWt3T1dWNGFWUklPRXRyZG5oT1JXaFFla3hrZW5rd1VGTmxSV1o0WDJsVFdXeE1aRmxKUmtWVU4yb3hNVTV2TFRGeU1rVjZRa05wVVRWdWRGSXhNMUVpZlN3aWNIVnljRzl6WlhNaU9sc2lZWFYwYUdWdWRHbGpZWFJwYjI0aUxDSmhjM05sY25ScGIyNU5aWFJvYjJRaVhTd2lkSGx3WlNJNklrcHpiMjVYWldKTFpYa3lNREl3SW4xZGZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVORVJsRlFabmhTUm5Oc2NrRkliVm80YVhOUWJFNDRRelpLVW1SemVuUTBabkkwYURsSU5HUm1NVlpuSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEJTRE14TkZkcVJUTkJhVFJoTFhNeVNtOUhjWFpqUzFWcFRFUmZNVEpWWjNWeFkwWTFiVWR6Um5aMFp5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFTMXBka1pxVFRaTGRteDJZVXRVT0dkQ2EzQkphelpMWmt4dk9VbDVNR28wWVdobWFpMXJUMGwyV2xFaWZTd2lkSGx3WlNJNkltTnlaV0YwWlNKOSIsCiAgICAibmFtZSI6ICJBY21lIElzc3VlciIKICB9LAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVDcmVkZW50aWFsIiwKICAgICJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCIKICBdCn0= |


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
    Then "1" credentials are issued
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
    Then "1" credentials are issued
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
