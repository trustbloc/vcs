#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_rest
Feature: Using VC REST API

  @e2e
  Scenario Outline: Store, retrieve, verify credential and presentation using different kind of profiles
    Given Profile "<profile>" is created with DID "<did>", privateKey "<privateKey>", signatureHolder "<signatureHolder>", uniRegistrar '<uniRegistrar>', didMethod "<didMethod>" and signatureType "<signatureType>"
    And   We can retrieve profile "<profile>" with DID "<didMethod>" and signatureType "<signatureType>"
    And   New verifiable credential is created from "<credential>" under "<profile>" profile
    And   That credential is stored under "<profile>" profile
    Then  We can retrieve credential under "<profile>" profile
    And   Now we verify that credential for checks "proof,status" is "successful" with message "proof,status"
    And   Now we verify that "JWS" signed with "<signatureType>" presentation for checks "proof" is "successful" with message "proof"
    And   Now we verify that "ProofValue" signed with "<signatureType>" presentation for checks "proof" is "successful" with message "proof"
    Then  Update created credential status "Revoked" and status reason "Disciplinary action"
    And   Now we verify that credential for checks "proof,status" is "failed" with message "Revoked"
    Examples:
      | profile              | credential                   | did                                                              | privateKey                                                                               | signatureHolder |                           uniRegistrar                                                                                                                        |  didMethod      |      signatureType      |
      | myprofile_ud         | university_degree.json       |                                                                  |                                                                                          | ProofValue      |       {"driverURL":"http://uni-registrar-web:9080/1.0/register?driver-did-method-rest"}                                                                       | did:trustbloc   |   JsonWebSignature2020  |
      | myprofile_prc        | permanent_resident_card.json |                                                                  |                                                                                          | ProofValue      |          {"driverURL":"http://uni-registrar-web:9080/1.0/register?driver-did-method-rest"}                                                                    | did:trustbloc   |   JsonWebSignature2020  |
      | myprofilewithdidv1   | university_degree.json       |                                                                  |                                                                                          | JWS             |       {"driverURL":"http://uni-registrar-web:9080/1.0/register?driver-universalregistrar/driver-did-v1","options": {"ledger": "test", "keytype": "ed25519"}}  | did:v1:test:nym |    Ed25519Signature2018 |
      | myprofilewithdidelem | university_degree.json       | did:elem:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ          | 5AcDTQT7Cdg1gBvz8PQpnH3xEbLCE1VQxAJV5NjVHvNjsZSfn4NaLZ77mapoi4QwZeBhcAA7MQzaFYkzJLfGjNnR | JWS             |                                                                                                                                                               | did:elem        |    Ed25519Signature2018 |
      | myprofilewithdidsov  | university_degree.json       |                                                                  |                                                                                          | JWS             |       {"driverURL":"https://uniregistrar.io/1.0/register?driver-universalregistrar/driver-did-sov","options": {"network":"danube"}}                           | did:sov:danube  |    Ed25519Signature2018 |


  @store_retrieve_vcs
  Scenario Outline: Store, retrieve verifiable credentials
    When  Given "<verifiable credential>" is stored under "<profile>" profile
    Then  We can retrieve credential under "<profile>" profile
    Examples:
      | profile               | verifiable credential  |
      | transmute-profile     | transmute_vc1.json     |
      | danubetech-profile    | danubetech_vc1.json    |
      | digitalbazaar-profile | digitalbazaar_vc1.json |
