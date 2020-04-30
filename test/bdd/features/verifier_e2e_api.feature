#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@verifier_rest
Feature: Verifier VC REST API

  @verifyCred_api
  Scenario Outline: Verify Credential
    Given "Alice" has her "<credential>" issued as "<verifiable credential>"
    Then  Employer verifies the verifiable credential provided by "Alice"
    Examples:
    Examples:
      | credential                      | verifiable credential  |
      | university_degree.json          |                        |
      | permanent_resident_card.json    |                        |
      | certified_mill_test_report.json |                        |
      | university_degree.json          | transmute_vc1.json     |
      | permanent_resident_card.json    | transmute_vc2.json     |
      | university_degree.json          | danubetech_vc1.json    |
      | permanent_resident_card.json    | danubetech_vc2.json    |
      | permanent_resident_card.json    | digitalbazaar_vc1.json |

  @verifyPresentation_api
  Scenario Outline: Verify Presentation
    Given "Alice" has her "<credential>" issued as "<verifiable credential>" and presentable as "<verifiable presentation>"
    Then  Employer verifies the verifiable presentation provided by "Alice"
    Examples:
      | credential                   | verifiable credential | verifiable presentation |
      | university_degree.json       |                       |                         |
      | permanent_resident_card.json |                       |                         |
      | university_degree.json       | transmute_vc1.json    |                         |
      | permanent_resident_card.json | transmute_vc2.json    |                         |
      | university_degree.json       | transmute_vc1.json    | transmute_vp1.json      |
      | permanent_resident_card.json | transmute_vc2.json    | transmute_vp2.json      |
