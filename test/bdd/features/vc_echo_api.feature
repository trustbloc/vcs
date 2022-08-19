#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_rest_echo
Feature: VC REST API using Echo web framework
  Scenario: VC server is up and running
    When I make an HTTP GET to "http://localhost:8075/healthcheck"
    Then I receive response with status code "200"
     And response contains "status" with value "success"
