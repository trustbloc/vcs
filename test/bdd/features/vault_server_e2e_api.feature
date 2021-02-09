#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vault_server
Feature: Vault server API

  @vault_server_healthcheck
  Scenario: Vault server healthcheck
    When an HTTP GET is sent to "http://localhost:9099/healthcheck"
    Then the JSON path "status" of the response equals "success"

  @vault_server_create
  Scenario: Creates a vault
    When Create a new vault using the vault server "http://localhost:9099"
    Then Save a document with the following id "M3aS9xwj8ybCwHkEiCJJR1"
    And Check that a document with id "M3aS9xwj8ybCwHkEiCJJR1" is stored
