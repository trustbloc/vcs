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
    And   Issuer with id "bank_issuer" is authorized as a Profile user
    And   Issuer registers Client for vcs oidc interactions
    And   User creates the wallet

  Scenario: OIDC credential issuance and verification
    When Issuer initiates credential issuance using authorization code flow
    Then Issuer receives initiate issuance URL

    When User interacts with Wallet to initiate OIDC credential issuance
    Then Wallet receives an access token

#    When Wallet requests credential for claim data using access token
#    Then Wallet receives a valid credential

    And   New verifiable credentials is created from table:
      | IssuerProfile             | Organization | Credential             | VCFormat      |
      | i_myprofile_ud_es256k_jwt | test_org     | university_degree.json | jwt_vc_json   |
    And User saves credentials into the wallet

    When User interacts with Verifier and initiate OIDC4VP interaction under "v_myprofile_jwt" profile for organization "test_org"
    Then User receives authorization request

    When User invokes authorization request using Wallet
    Then Wallet queries credential that match authorization and display them for User

    When User gives a consent
    Then Wallet sends authorization response
    And Verifier from organization "test_org" retrieves interactions claims