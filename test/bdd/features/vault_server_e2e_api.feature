#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vault_server
Feature: Vault server API

  @vault_server_create
  Scenario: Creates a vault
    When Create a new vault using the vault server "http://localhost:9099"
