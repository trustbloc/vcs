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
    Given Profile "<profile>" is created with DID "<did>" and privateKey "<privateKey>"
    And   We can retrieve profile "<profile>" with DID "<did>"
    And   New credential is created under "<profile>" profile
    And   That credential is stored under "<profile>" profile
    Then  We can retrieve credential under "<profile>" profile
    And   Now we verify that credential with verified flag is "true" and verified msg contains "success"
    And   Now we verify that presentation with verified flag is "true" and verified msg contains "success"
    Then  Update created credential status "Revoked" and status reason "Disciplinary action"
    And   Now we verify that credential with verified flag is "false" and verified msg contains "Revoked"
    Examples:
      | profile | did | privateKey |
      | myprofile |   |            |
      | myprofilewithdid | did:v1:test:nym:z6MkiJFtehU8FcTu6hAKiBEzzD5LfZHRR9wiiyJCgkbCZ6XN | 4Gn9Ttw6Lf3oFBFqJNNdLFMc4mUbbpCYLNSQFGAxaLBXiJ6DuZpJ8qsZGaHqwyBptxJMEB8nFiqHDZ419XHHxudY |
