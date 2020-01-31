#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_rest
Feature: Using VC REST API

  @e2e
  Scenario: Store, retrieve, and verify credential.
    Given Profile "MyProfile" is created
    And   We can retrieve profile "MyProfile"
    And   New credential is created under "MyProfile" profile
    And   That credential is stored under "MyProfile" profile
    Then  We can retrieve credential under "MyProfile" profile
    And   Now we verify that credential
