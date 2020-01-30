#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_rest
Feature: Using VC REST API

  @create_profile
  Scenario: Create a profile.
    Then  Send request to create a profile with profile request "${PROFILE_REQUEST1}" and receive the profile response "${EXPECTED_PROFILE_RESPONSE1}"

  @get_profile
  Scenario: Get a previously stored profile.
    Given Send request to create a profile with profile request "${PROFILE_REQUEST2}" and receive the profile response "${EXPECTED_PROFILE_RESPONSE2}"
    Then  Send request to get a profile with id "profile2" and receive the profile response "${EXPECTED_PROFILE_RESPONSE2}"

  @create_credential
  Scenario: Create a credential under a previously created profile.
  Given Send request to create a profile with profile request "${PROFILE_REQUEST3}" and receive the profile response "${EXPECTED_PROFILE_RESPONSE3}"
  Then  Send request to create a credential with credential request "${CREDENTIAL_REQUEST1}" and receive a verified credential with issuer ID "did:peer:22" and issuer name "profile3"

  @store_credential
  Scenario: Store a credential after creating it.
    Given Send request to create a profile with profile request "${PROFILE_REQUEST4}" and receive the profile response "${EXPECTED_PROFILE_RESPONSE4}"
    Given Send request to create a credential with credential request "${CREDENTIAL_REQUEST2}" and receive a verified credential with issuer ID "did:peer:22" and issuer name "profile4"
    Then  Send request to store a credential with StoreVCRequest "${STORE_VC_REQUEST1}"

  @retrieve_credential
  Scenario: Retrieve a credential after creating it.
    Given Send request to create a profile with profile request "${PROFILE_REQUEST5}" and receive the profile response "${EXPECTED_PROFILE_RESPONSE5}"
    Given Send request to create a credential with credential request "${CREDENTIAL_REQUEST3}" and receive a verified credential with issuer ID "did:peer:22" and issuer name "profile5"
    Given Send request to store a credential with StoreVCRequest "${STORE_VC_REQUEST2}"
    Then  Send request to retrieve a credential with id "https://example.com/credentials/1872" under profile "profile5" and receive VC with issuer ID "did:example:76e12ec712ebc6f1c221ebfeb1f" and issuer name "Example University"

  @verify_credential
  Scenario: Verify a credential.
    Then  Verify the credential "${VALID_VC}"