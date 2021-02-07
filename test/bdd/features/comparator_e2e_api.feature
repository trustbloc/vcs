#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@comparator_rest
Feature: Comparator_REST API

  @comparator_healthcheck
  Scenario: Comparator healthcheck
    When an HTTP GET is sent to "https://localhost:8065/healthcheck"
    Then the JSON path "status" of the response equals "success"

  @comparator_e2e
  Scenario: Comparator
    Then Check comparator config is created
