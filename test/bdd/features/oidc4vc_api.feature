#
# Copyright Avast Software. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@oidc4vc_rest
Feature: OIDC4VC REST API

  Background:
    Given Organization "test_org" has been authorized with client id "f13d1va9lp403pb9lyj89vk55" and secret "ejqxi9jb1vew2jbdnogpjcgrz"
    And   Issuer with id "bank_issuer/v1.0" is authorized as a Profile user
    And   Issuer registers Client for vcs oidc interactions
    And   User creates the wallet

  Scenario: OIDC credential issuance and verification
    When Issuer initiates credential issuance using authorization code flow
    Then Issuer receives initiate issuance URL

    When User interacts with Wallet to initiate OIDC credential issuance
    Then Wallet receives an access token

    And   New verifiable credentials is created from table:
      | IssuerProfile                   | Organization | Credential                            | VCFormat       |
      | i_myprofile_ud_es256_sdjwt/v1.0 | test_org     | university_degree.json                | jwt_vc_json-ld |
      | i_myprofile_ud_es256k_jwt/v1.0  | test_org     | university_degree.json                | jwt_vc_json-ld |
    And User saves credentials into the wallet

    When User interacts with Verifier and initiate OIDC4VP interaction under "v_myprofile_jwt/v1.0" profile for organization "test_org"
    Then User receives authorization request

    When User invokes authorization request using Wallet
    Then Wallet queries credential that match authorization and display them for User

    When User gives a consent
    Then Wallet sends authorization response
    And Verifier from organization "test_org" retrieves interactions claims

  Scenario: OIDC credential issuance and verification (Invalid Claims)
    When Issuer initiates credential issuance using authorization code flow
    Then Issuer receives initiate issuance URL

    When User interacts with Wallet to initiate OIDC credential issuance
    Then Wallet receives an access token

    And   New verifiable credentials is created from table:
      | IssuerProfile                   | Organization | Credential                            | VCFormat       |
      | i_myprofile_ud_es256k_jwt/v1.0  | test_org     | university_degree_invalid_claims.json | jwt_vc_json-ld |
    And User saves credentials into the wallet

    When User interacts with Verifier and initiate OIDC4VP interaction under "v_myprofile_jwt/v1.0" profile for organization "test_org"
    Then User receives authorization request

    When User invokes authorization request using Wallet
    Then Wallet queries credential that match authorization and display them for User

    When User gives a consent
    Then Wallet sends authorization response and receives an error