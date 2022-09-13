#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@issuer_rest_v1
Feature: Issuer VC REST API
  @issuerProfileRecreationV1
  Scenario: Delete and recreate issuer profile
    Given "Charlie" sends request to create an issuer profile with the organization "National Bank"
    And   "Charlie" deletes the issuer profile
    Then  "Charlie" can recreate the issuer profile with the organization "National Bank"


  @issuerProfileUpdateV1
  Scenario: Create and update issuer profile
    Given "Charlie" sends request to create an issuer profile with the organization "National Bank"
    And   "Charlie" updates the issuer profile name to "New Name"

  @issuerProfileActivateDeactivateV1
  Scenario: Create and update issuer profile
    Given "Charlie" sends request to create an issuer profile with the organization "National Bank"
    And   "Charlie" deactivates the issuer profile
    And   "Charlie" activates the issuer profile