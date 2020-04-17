#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Below features are currently failing due to issues in third party systems.
#  TODO: below examples should be uncommented after [https://github.com/trustbloc/edge-service/issues/229] is resolved
@interop
@third_party_verifier
Feature: Verifier verifiable credentials and presentations in third party endpoints

  @verify_credentials
  Scenario Outline: Verify credentials using thirdparty verifier endpoints
    Given "Alice" has her "<credential>" issued as verifiable credential using "<did>" and "<private key>"
    Then  "<verifier>" verifies the verifiable credential provided by "Alice"
    Examples:
    Examples:
      | credential                   | verifier                                        | did                                                      | private key                                                                              |
      | university_degree.json       | http://localhost:8069/verifier/credentials      | did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd | 28xXA4NyCQinSJpaZdSuNBM4kR2GqYb8NPqAtZoGCpcRYWBcDXtzVAzpZ9BAfgV334R2FC383fiHaWWWAacRaYGs |
      | permanent_resident_card.json | http://localhost:8069/verifier/credentials      | did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd | 28xXA4NyCQinSJpaZdSuNBM4kR2GqYb8NPqAtZoGCpcRYWBcDXtzVAzpZ9BAfgV334R2FC383fiHaWWWAacRaYGs |
      | university_degree.json       | https://vc.transmute.world/verifier/credentials | did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd | 28xXA4NyCQinSJpaZdSuNBM4kR2GqYb8NPqAtZoGCpcRYWBcDXtzVAzpZ9BAfgV334R2FC383fiHaWWWAacRaYGs |
      | permanent_resident_card.json | https://vc.transmute.world/verifier/credentials | did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd | 28xXA4NyCQinSJpaZdSuNBM4kR2GqYb8NPqAtZoGCpcRYWBcDXtzVAzpZ9BAfgV334R2FC383fiHaWWWAacRaYGs |
#      | permanent_resident_card.json | https://univerifier.io/danubetech/credential-verifier/0.0.1/verifications | did:v1:test:nym:z6MkrNtSzgP1j3UrY44qktv7kFkN5RGjPHGCtwry6FUkgacR | 5vckXBtWX4Fp5N1q9UfAydDm5MoY9CZjbGNnQycPNSugstn2RMJG4dY1eoUWgDSBjNvknAsea8hwLWN8m7LtmLvK |
#      | permanent_resident_card.json | https://verifier.interop.digitalbazaar.com/verifiers/credentials          | did:v1:test:nym:z6MkrNtSzgP1j3UrY44qktv7kFkN5RGjPHGCtwry6FUkgacR | 5vckXBtWX4Fp5N1q9UfAydDm5MoY9CZjbGNnQycPNSugstn2RMJG4dY1eoUWgDSBjNvknAsea8hwLWN8m7LtmLvK |

#  TODO add digitalbazaar and danubetech VPs in examples below once [https://github.com/trustbloc/edge-service/issues/229] is resolved
  @verify_presentations
  Scenario Outline: Verify credentials using thirdparty verifier endpoints
    Given "Alice" has her "<credential>" issued as verifiable presentation using "<did>" and "<private key>"
    Then  "<verifier>" verifies the verifiable presentation provided by "Alice"
    Examples:
    Examples:
      | credential                   | verifier                                          | did                                                      | private key                                                                              |
      | university_degree.json       | https://vc.transmute.world/verifier/presentations | did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd | 28xXA4NyCQinSJpaZdSuNBM4kR2GqYb8NPqAtZoGCpcRYWBcDXtzVAzpZ9BAfgV334R2FC383fiHaWWWAacRaYGs |
      | permanent_resident_card.json | https://vc.transmute.world/verifier/presentations | did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd | 28xXA4NyCQinSJpaZdSuNBM4kR2GqYb8NPqAtZoGCpcRYWBcDXtzVAzpZ9BAfgV334R2FC383fiHaWWWAacRaYGs |
