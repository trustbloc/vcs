#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_dev_api
Feature: Request DID Config
  Scenario: Request DID Config for Verifier
    When I request did config for "verifier" with ID "v_myprofile_ldp"
    Then I receive response with status code "200"
    And response contains "status" with value "success"
