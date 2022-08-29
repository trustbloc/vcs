#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@verifier_profile_rest
Feature: Verifier Profile Management REST API
  Scenario: Create a new verifier profile
    When organization "org1" creates a verifier profile with data from "verifier_profile_create.json"
    Then verifier profile is created
     And verifier profile matches "verifier_profile_created.json"

  Scenario: Get verifier profile by ID
    Given organization "org1" has a verifier profile with data from "verifier_profile_create.json"
    When organization "org1" gets a verifier profile by ID
    Then verifier profile is returned
     And verifier profile matches "verifier_profile_created.json"

  Scenario: Update an existing verifier profile
    Given organization "org1" has a verifier profile with data from "verifier_profile_create.json"
    When organization "org1" updates a verifier profile with data from "verifier_profile_update.json"
    Then verifier profile is updated
     And verifier profile matches "verifier_profile_updated.json"

  Scenario: Delete verifier profile
    Given organization "org1" has a verifier profile with data from "verifier_profile_create.json"
    When organization "org1" deletes a verifier profile
    Then verifier profile is deleted

  Scenario: Activate/deactivate verifier profile
    Given organization "org1" has a verifier profile with data from "verifier_profile_create.json"
    When organization "org1" deactivates a verifier profile
    Then verifier profile is deactivated
    When organization "org1" activates a verifier profile
    Then verifier profile is activated
