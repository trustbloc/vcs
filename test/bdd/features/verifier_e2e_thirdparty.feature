#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@verifier_thirdparty
Feature: Verifier verifiable credentials and presentations in third party endpoints

  @verify_credentials
  Scenario Outline: Verify credentials using thirdparty verifier endpoints
    Given "Alice" has her "<credential>" issued as verifiable using "<did>" and "<private key>"
    Then  "<verifier>" verifies the verifiable credential provided by "Alice"
    Examples:
    Examples:
      | credential                   | verifier                                        | did                                                     | private key                                                                              |
      | university_degree.json       | https://vc.transmute.world/verifier/credentials | did:elem:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ | 5AcDTQT7Cdg1gBvz8PQpnH3xEbLCE1VQxAJV5NjVHvNjsZSfn4NaLZ77mapoi4QwZeBhcAA7MQzaFYkzJLfGjNnR |
      | permanent_resident_card.json | https://vc.transmute.world/verifier/credentials | did:elem:EiAWdU2yih6NA2IGnLsDhkErZ8aQX6b8yKt7jHMi-ttFdQ | 5AcDTQT7Cdg1gBvz8PQpnH3xEbLCE1VQxAJV5NjVHvNjsZSfn4NaLZ77mapoi4QwZeBhcAA7MQzaFYkzJLfGjNnR |
