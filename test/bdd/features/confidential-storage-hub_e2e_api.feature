#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@confidential-storage-hub
Feature: Comparator_REST API

  @healthcheck
  Scenario: Healthcheck
    When an HTTP GET is sent to "https://localhost:8095/healthcheck"
    Then the JSON path "status" of the response equals "success"
