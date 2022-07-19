#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@holder_rest
Feature: Holder VC REST API
  @holderProfileRecreation
  Scenario Outline: Delete and recreate Holder profile
    Given Client sends request to create a holder profile with ID "<profileID>"
    And   Client deletes the holder profile with ID "<profileID>"
    Then  Client can recreate the holder profile with ID "<profileID>"
    Examples:
      | profileID    |
      | test_profile |

  # TODO example 'holderwithdidv1' to be uncommented after fixing Issue[#429]
  # TODO example 'holderwithdidsov' to be uncommented after fixing Issue[#454]
  @holder_api
  Scenario Outline: Holder APIs
    Given Holder Profile "<profile>" is created with DID "<did>", privateKey "<privateKey>", keyID "<keyID>", signatureHolder "<signatureHolder>", didMethod "<didMethod>", signatureType "<signatureType>" and keyType "<keyType>"
    And   Holder profile "<profile>" can be retrieved with DID "<didMethod>" and signatureType "<signatureType>"
    Then  Holder "<profile>" generates presentation for the VC received from the Government
    Examples:
      | profile                  | did                                                      | privateKey                                                                               | keyID                                                                                                      | signatureHolder |  didMethod      |    signatureType     |  keyType |
      | holder_local_ed25519_jws |                                                          |                                                                                          |                                                                                                            | JWS             | did:orb         | Ed25519Signature2018 |  Ed25519 |
      | holder_local_p256_pv     |                                                          |                                                                                          |                                                                                                            | ProofValue      | did:orb         | JsonWebSignature2020 |  P256    |
      | holder_local_ed25519     |                                                          |                                                                                          |                                                                                                            | JWS             | did:orb         | JsonWebSignature2020 |  Ed25519 |
      | holder_local_p256        |                                                          |                                                                                          |                                                                                                            | JWS             | did:orb         | JsonWebSignature2020 |  P256    |
      | holderwithdidkey         | did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd | 28xXA4NyCQinSJpaZdSuNBM4kR2GqYb8NPqAtZoGCpcRYWBcDXtzVAzpZ9BAfgV334R2FC383fiHaWWWAacRaYGs |  did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd | JWS             | did:key         | Ed25519Signature2018 |  Ed25519 |
