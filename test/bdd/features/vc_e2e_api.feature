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
    Given Profile "<profile>" is created with DID "<did>", privateKey "<privateKey>" and signatureHolder "<signatureHolder>"
    And   We can retrieve profile "<profile>" with DID "<did>"
    And   New verifiable credential is created from "<credential>" under "<profile>" profile
    And   That credential is stored under "<profile>" profile
    Then  We can retrieve credential under "<profile>" profile
    And   Now we verify that credential for checks "proof,status" is "successful" with message "proof,status"
    And   Now we verify that "JWS" signed presentation for checks "proof" is "successful" with message "proof"
    And   Now we verify that "ProofValue" signed presentation for checks "proof" is "successful" with message "proof"
    Then  Update created credential status "Revoked" and status reason "Disciplinary action"
    And   Now we verify that credential for checks "proof,status" is "failed" with message "Revoked"
    Examples:
      | profile              | credential                   | did                                                              | privateKey                                                                               | signatureHolder |
      | myprofile_ud         | university_degree.json       |                                                                  |                                                                                          | ProofValue      |
      | myprofile_prc        | permanent_resident_card.json |                                                                  |                                                                                          | ProofValue      |
      | myprofilewithdidv1   | university_degree.json       | did:v1:test:nym:z6MkrNtSzgP1j3UrY44qktv7kFkN5RGjPHGCtwry6FUkgacR | 5vckXBtWX4Fp5N1q9UfAydDm5MoY9CZjbGNnQycPNSugstn2RMJG4dY1eoUWgDSBjNvknAsea8hwLWN8m7LtmLvK | JWS             |
      | myprofilewithdidelem | university_degree.json       | did:elem:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ          | 5AcDTQT7Cdg1gBvz8PQpnH3xEbLCE1VQxAJV5NjVHvNjsZSfn4NaLZ77mapoi4QwZeBhcAA7MQzaFYkzJLfGjNnR | JWS             |
      | myprofilewithdidsov  | university_degree.json       | did:sov:danube:CDEabPCipwE51bg7KF9yXt                            | 22WXAJuENXAZUKZuRceBP3S6G5mrbah9WvNxRan23HvLZ7kHMBMvZoAqAwbBo9WhkYdKVa11cCySH9m2HRmFXeaq | JWS             |


  @store_retrieve_vcs
  Scenario Outline: Store, retrieve verifiable credentials
    When  Given "<verifiableCredential>" is stored under "<profile>" profile
    Then  We can retrieve credential under "<profile>" profile
    Examples:
      | profile           | verifiableCredential |
      | transmute-profile | transmute_vc1.json    |