#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@w3c_workflow
Feature: CHAPI Workflow - API only

  @chapi_api_flow
  Scenario Outline: CHAPI Workflow - API only (https://github.com/w3c-ccg/vc-examples/tree/master/docs/chapi-http-edu)
    Given "<issuerProfile>" has a profile with signature type "<issuerSignType>" and DID key type "<issuerKeyType>" created with the Issuer HTTP Service
    And   "<holderProfile>" has a holder profile with signature type "<holderSignType>" and DID key type "<holderKeyType>"
    And   "<issuerProfile>" sends DIDAuth request to "<holderProfile>" for authentication
    And   "<holderProfile>" sends response to DIDAuth request from "<issuerProfile>"
    Then  "<issuerProfile>" verifies the DIDAuth response from "<holderProfile>"
    Then  "<issuerProfile>" issues the "<flow>" with credential "<credential>" to "<holderProfile>"
    And   "<holderProfile>" stores the "<flow>" in wallet
    When  "<verifier>" sends DIDAuth request to "<holderProfile>" for authentication
    And   "<holderProfile>" sends response to DIDAuth request from "<verifier>"
    Then  "<verifier>" verifies the DIDAuth response from "<holderProfile>"
    Then  "<verifier>" verifies the "<flow>" presented by "<holderProfile>"
    Examples:
      | flow                        | issuerProfile         | holderProfile     | verifier        | credential                       | issuerKeyType | issuerSignType        | holderKeyType | holderSignType          |
      | Education Degree            | university            | alice             | acme            | university_degree.json           | Ed25519       | Ed25519Signature2018  | Ed25519       | Ed25519Signature2018    |
      | Permanent Resident Card     | government            | bob               | immigrationDept | permanent_resident_card.json     | Ed25519       | Ed25519Signature2018  | Ed25519       | Ed25519Signature2018    |
      | Permanent Resident Card     | government_ed25519    | bob_p256          | immigrationDept | permanent_resident_card.json     | Ed25519       | Ed25519Signature2018  | P256          | JsonWebSignature2020    |
      | Certified Mill Test Report  | qualityinc            | stark_industries  | customsDept     | certified_mill_test_report.json  | P256          | JsonWebSignature2020  | Ed25519       | JsonWebSignature2020    |
