#
# Copyright Avast Software. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@oidc4vc_rest
Feature: OIDC4VC REST API
  Scenario: OIDC4VC issuance using authorization code flow
    Given Organization "test_bank" has been authorized with client id "test_bank" and secret "test-bank-secret"
     And  issuer has a profile set up on vcs
     And  client is registered as a public client on vcs

    When issuer initiates credential issuance using authorization code flow
    Then initiate issuance URL is returned

    When client requests an authorization code using data from initiate issuance URL
     And user authenticates on issuer IdP
#     And user gives a consent to release claim data
    Then client receives an authorization code

#    When client exchanges authorization code for an access token
#    Then client receives an access token

#    When client requests credential for claim data
#    Then client receives a valid credential
