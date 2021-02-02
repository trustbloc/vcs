#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@confidential-storage-hub
Feature: Comparator_REST API
  Background: Confidential Storage Hub is ready
    When an HTTP GET is sent to "https://localhost:8095/healthcheck"
    Then the JSON path "status" of the response equals "success"

  @confidential-storage-hub-profiles
  Scenario: Create profile
    When the user requests a new confidential-storage-hub profile
    Then the confidential-storage-hub profile is created
