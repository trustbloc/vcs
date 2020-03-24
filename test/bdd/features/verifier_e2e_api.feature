#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@verifier_rest
Feature: Verifier VC REST API

  @e2e
  Scenario: Verify Credential
    Given "Alice" has stored her transcript from the University
    Then  Employer verifies the transcript provided by "Alice"
