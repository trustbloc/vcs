#
# Copyright Avast Software. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@oidc4vc_rest
Feature: OIDC4VC REST API
  Scenario: Credential issuance using OIDC4VC authorization code flow
    Given issuer with id "bank_issuer" authorized as a profile user
    And  client registered as a public client to vcs oidc

    When issuer initiates credential issuance using authorization code flow
    Then initiate issuance URL is returned

    When client requests an authorization code using data from initiate issuance URL
    And user authenticates on issuer IdP
#     And user gives a consent to release claim data
    Then client receives an authorization code

    When client exchanges authorization code for an access token
    Then client receives an access token

  Scenario: Credential issuance using OIDC4VC pre-authorization code flow
    Given issuer with id "bank_issuer" wants to issue credentials to his client with pre-auth code flow

    When issuer sends request to initiate-issuance
    Then issuer receives response with oidc url
    And issuer represent this url to client as qrcode

    When client scans qrcode
    Then client should receive access token for further interactions with vc api

#    When client requests credential for claim data
#    Then client receives a valid credential
