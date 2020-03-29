#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_rest
Feature: Using VC REST API

  @e2e
  Scenario Outline: Store, retrieve, and verify credential and presentation.
    Given Profile "<profile>" is created with DID "<did>", privateKey "<privateKey>" and signatureHolder "<signatureHolder>"
    And   We can retrieve profile "<profile>" with DID "<did>"
    And   New credential is created under "<profile>" profile
    And   That credential is stored under "<profile>" profile
    Then  We can retrieve credential under "<profile>" profile
    And   Now we verify that credential with verified flag is "true" and verified msg contains "success"
    And   Now we verify that "JWS" signed presentation with verified flag is "true" and verified msg contains "success"
    And   Now we verify that "ProofValue" signed presentation with verified flag is "true" and verified msg contains "success"
    Then  Update created credential status "Revoked" and status reason "Disciplinary action"
    And   Now we verify that credential with verified flag is "false" and verified msg contains "Revoked"
    Examples:
      | profile | did | privateKey | signatureHolder |
      | myprofile |   |            | ProofValue |
      | myprofilewithdidv1 | did:v1:test:nym:z6MkrNtSzgP1j3UrY44qktv7kFkN5RGjPHGCtwry6FUkgacR | 5vckXBtWX4Fp5N1q9UfAydDm5MoY9CZjbGNnQycPNSugstn2RMJG4dY1eoUWgDSBjNvknAsea8hwLWN8m7LtmLvK | JWS |
      | myprofilewithdidelem | did:elem:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ | 5AcDTQT7Cdg1gBvz8PQpnH3xEbLCE1VQxAJV5NjVHvNjsZSfn4NaLZ77mapoi4QwZeBhcAA7MQzaFYkzJLfGjNnR | JWS |
      | myprofilewithdidsov | did:sov:danube:CDEabPCipwE51bg7KF9yXt | 22WXAJuENXAZUKZuRceBP3S6G5mrbah9WvNxRan23HvLZ7kHMBMvZoAqAwbBo9WhkYdKVa11cCySH9m2HRmFXeaq | JWS |
