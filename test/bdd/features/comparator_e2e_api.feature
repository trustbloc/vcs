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
    When Create a new vault using the vault server "https://localhost:9099"
    Then Save a document with the following id "M3aS9xwj8ybCwHkEiCJJR2"
    Then Save a document with the following id "M3aS9xwj8ybCwHkEiCJJR3"
    And Check that a document with id "M3aS9xwj8ybCwHkEiCJJR2" is stored
    And Check that a document with id "M3aS9xwj8ybCwHkEiCJJR3" is stored
    Then Compare two docs with doc1 id "M3aS9xwj8ybCwHkEiCJJR2" and doc2 id "M3aS9xwj8ybCwHkEiCJJR3"
