#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_dev_api
Feature: Request DID Config
  Scenario: Request DID Config for Issuer with ldp
    When I request did config for "issuer" with ID "i_myprofile_ud_P256k1" and type "ldp"
    Then I receive response with status code "200" for didconfig

  Scenario: Request DID Config for Issuer with JWT
    When I request did config for "issuer" with ID "i_myprofile_ud_es256_jwt" and type "jwt"
    Then I receive response with status code "200" for didconfig


  Scenario: Request DID Config for Verifier
    When I request did config for "verifier" with ID "v_myprofile_ldp" and type "ldp"
    Then I receive response with status code "200" for didconfig