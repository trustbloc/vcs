#
# Copyright Avast Software. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@oidc4ci_rest
Feature: OIDC4CI REST API

  Scenario: Credential issuance using OIDC4CI authorization code flow
    Given issuer with id "bank_issuer" authorized as a profile user
     And  client registered as a public client to vcs oidc

    When issuer initiates credential issuance using authorization code flow
    Then initiate issuance URL is returned

    When client requests an authorization code using data from initiate issuance URL
     And user authenticates on issuer IdP
    Then client receives an authorization code

    When client exchanges authorization code for an access token
    Then client receives an access token

    When client requests credential for claim data
    Then client receives a valid credential

  Scenario Outline: Credential issuance using OIDC4CI pre-authorization code flow
    Given issuer with id "<issuerName>" wants to issue credentials to his client with pre-auth code flow

    When issuer sends request to initiate-issuance with requirePin "<requirePin>"
    Then issuer receives response with oidc url
     And issuer represent this url to client as qrcode

    When client scans qrcode
    Then client should receive access token for further interactions with vc api

    When client requests credential for claim data with pre-authorize flow
    Then client receives a valid credential with pre-authorize flow
     And claim data are removed from the database

    Examples:
      | issuerName          | requirePin |
      | bank_issuer         | true       |
      | bank_issuer         | false      |
      | issuer_without_oidc | true       |