#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@verifier_rest
Feature: Verifier VC REST API
  @verifierProfileRecreation
  Scenario Outline: Delete and recreate verifier profile
    Given Client sends request to create a verifier profile with ID "<profileID>"
    And   Client deletes the verifier profile with ID "<profileID>"
    Then  Client can recreate the verifier profile with ID "<profileID>"
    Examples:
      | profileID    |
      | test_profile |

  @verifyCred_api
  Scenario Outline: Verify Credential
    Given "<verifierProfile>" has a profile
    And   "Alice" has her "<credential>" issued as "<verifiable credential>"
    Then  "<verifierProfile>" verifies the verifiable credential provided by "Alice"
    Examples:
    Examples:
      | verifierProfile     | credential                      | verifiable credential  |
      | ud_trustbloc        | university_degree.json          |                        |
      | pr_trustbloc        | permanent_resident_card.json    |                        |
      | crude_trustbloc     | crude_product.json              |                        |
      | cmtr_trustbloc      | certified_mill_test_report.json |                        |
      | ud_transmute        | university_degree.json          | transmute_vc1.json     |
      | pr_transmute        | permanent_resident_card.json    | transmute_vc2.json     |
      | cmtr_transmute      | certified_mill_test_report.json | transmute_vc3.json     |
      | crude_transmute     | crude_product.json              | transmute_vc4.json     |
      | ud_danubetech       | university_degree.json          | danubetech_vc1.json    |
      | pr_danubetech       | permanent_resident_card.json    | danubetech_vc2.json    |
      | pr_digitalbazaar    | permanent_resident_card.json    | digitalbazaar_vc1.json |
      | ud_mavennet         | university_degree.json          | mavennet_vc1.json      |
      | pr_mavennet         | permanent_resident_card.json    | mavennet_vc2.json      |
      | cmtr_mavennet       | certified_mill_test_report.json | mavennet_vc3.json      |
      | crude_mavennet      | crude_product.json              | mavennet_vc4.json      |
      | ud_factom           | university_degree.json          | factom_vc1.json        |
      | pr_factom           | permanent_resident_card.json    | factom_vc2.json        |
      | cmtr_factom         | certified_mill_test_report.json | factom_vc3.json        |
      | crude_factom        | crude_product.json              | factom_vc4.json        |
      | ud_sicpa            | university_degree.json          | sicpa_vc1.json         |
      | pr_sicpa            | permanent_resident_card.json    | sicpa_vc2.json         |
      | crude_sicpa         | crude_product.json              | sicpa_vc3.json         |

  @verifyPresentation_api
  Scenario Outline: Verify Presentation
    Given "<verifierProfile>" has a profile
    And   "Alice" has her "<credential>" issued as "<verifiable credential>" and presentable as "<verifiable presentation>"
    Then  "<verifierProfile>" verifies the verifiable presentation provided by "Alice" is "successful" with message "proof"
    Examples:
      | verifierProfile                     | credential                      | verifiable credential  | verifiable presentation |
      | ud_vp_trustbloc                     | university_degree.json          |                        |                         |
      | pr_vp_trustbloc                     | permanent_resident_card.json    |                        |                         |
      | crude_vp_trustbloc                  | crude_product.json              |                        |                         |
      | cmtr_vp_trustbloc                   | certified_mill_test_report.json |                        |                         |
      | ud_vc_transmute_vp_trustbloc        | university_degree.json          | transmute_vc1.json     |                         |
      | pr_vc_transmute_vp_trustbloc        | permanent_resident_card.json    | transmute_vc2.json     |                         |
      | cmtr_vc_transmute_vp_trustbloc      | certified_mill_test_report.json | transmute_vc3.json     |                         |
      | crude_vc_transmute_vp_trustbloc     | crude_product.json              | transmute_vc4.json     |                         |
      | ud_vp_transmute                     | university_degree.json          | transmute_vc1.json     | transmute_vp1.json      |
      | pr_vp_transmute                     | permanent_resident_card.json    | transmute_vc2.json     | transmute_vp2.json      |
      | cmtr_vp_transmute                   | certified_mill_test_report.json | transmute_vc3.json     | transmute_vp3.json      |
      | crude_vp_transmute                  | crude_product.json              | transmute_vc4.json     | transmute_vp4.json      |
      | ud_vc_mavennet_vp_trustbloc         | university_degree.json          | mavennet_vc1.json      |                         |
      | pr_vc_mavennet_vp_trustbloc         | permanent_resident_card.json    | mavennet_vc2.json      |                         |
      | cmtr_vc_mavennet_vp_trustbloc       | certified_mill_test_report.json | mavennet_vc3.json      |                         |
      | crude_vc_mavennet_vp_trustbloc      | crude_product.json              | mavennet_vc4.json      |                         |
      | ud_vc_digitalbazaar_vp_trustbloc    | permanent_resident_card.json    | digitalbazaar_vc1.json |                         |
      | ud_vc_danubetech_vp_trustbloc       | university_degree.json          | danubetech_vc1.json    |                         |
      | pr_vc_danubetech_vp_trustbloc       | permanent_resident_card.json    | danubetech_vc2.json    |                         |
      # TODO failing Error: expected status code 200 but got status code 400 with response body {"checks":[{"check":"proof","error":"verifiable presentation proof validation error : verifiable credential proof validation error : decode new credential: check embedded proof: check linked data proof: resolve DID did:factom:5d0dd58757119dd437c70d92b44fbf86627ee275f0f2146c3d99e441da342d9f: did method read failed failed: unsupported response from DID resolver [500] header [] body [Resolve problem for did:factom:5d0dd58757119dd437c70d92b44fbf86627ee275f0f2146c3d99e441da342d9f: Cannot retrieve RESOLVE RESULT for did:factom:5d0dd58757119dd437c70d92b44fbf86627ee275f0f2146c3d99e441da342d9f from http://driver-did-factom:8080/1.0/identifiers/did:factom:5d0dd58757119dd437c70d92b44fbf86627ee275f0f2146c3d99e441da342d9f: Connect to driver-did-factom:8080 [driver-did-factom/10.100.7.228] failed: Connection refused (Connection refused)]"}]}
      #| ud_vc_factom_vp_trustbloc           | university_degree.json          | factom_vc1.json        |                         |
      #| pr_vc_factom_vp_trustbloc           | permanent_resident_card.json    | factom_vc2.json        |                         |
      #| cmtr_vc_factom_vp_trustbloc         | certified_mill_test_report.json | factom_vc3.json        |                         |
      #| crude_vc_factom_vp_trustbloc        | crude_product.json              | factom_vc4.json        |                         |
      | ud_vc_sicpa_vp_trustbloc            | university_degree.json          | sicpa_vc1.json         |                         |
      | pr_vc_sicpa_vp_trustbloc            | permanent_resident_card.json    | sicpa_vc2.json         |                         |
      | crude_vc_sicpa_vp_trustbloc         | crude_product.json              | sicpa_vc3.json         |                         |
      | ud_vp_mavennet                      | university_degree.json          | mavennet_vc1.json      | mavennet_vp1.json       |
      | pr_vp_mavennet                      | permanent_resident_card.json    | mavennet_vc2.json      | mavennet_vp2.json       |
      | cmtr_vp_mavennet                    | certified_mill_test_report.json | mavennet_vc3.json      | mavennet_vp3.json       |
      | crude_vp_mavennet                   | crude_product.json              | mavennet_vc4.json      | mavennet_vp4.json       |


  @revokePresentationCred_api
  Scenario Outline: Revoke Presentation Credential
    Given "<verifierProfile>" has a profile
    And   "Alice" has her "<credential>" issued as "<verifiable credential>" and presentable as "<verifiable presentation>"
    Then  "<verifierProfile>" verifies the verifiable presentation provided by "Alice" is "successful" with message "proof,status"
    Then  Revoke verifiable presentation credential status provided by "Alice"
    Then  "<verifierProfile>" verifies the verifiable presentation provided by "Alice" is "failed" with message "Revoked"
    Examples:
      | verifierProfile                     | credential                      | verifiable credential  | verifiable presentation |
      | ud_vp_trustbloc_revoke              | university_degree.json          |                        |                         |
