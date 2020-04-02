#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@verifier_rest
Feature: Verifier VC REST API

  @verifyCred_api
  Scenario Outline: Verify Credential
    Given "Alice" has stored her transcript "<verifiableCredential>" from the University
    Then  Employer verifies the transcript provided by "Alice"
    Examples:
    Examples:
      |   verifiableCredential  |
      |                         |
      |     transmute_vc.json   |

  @verifyPresentation_api
  Scenario Outline: Verify Presentation
    Given "Alice" has stored her transcript "<verifiablePresentation>" presented from the University
    Then  Employer verifies the transcript presented by "Alice"
    Examples:
      |   verifiablePresentation  |
      |                           |
      |     transmute_vp.json     |