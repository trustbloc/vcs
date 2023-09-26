#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@vc_stress
Feature: VC stress test
  @vc_stress_test
  Scenario: Stress test method
    When Profile "i_myprofile_ud_P256k1/v1.0" issuer has been authorized with username "profile-user-issuer-1" and password "profile-user-issuer-1-pwd"
    And Profile "v_myprofile_ldp/v1.0" verifier has been authorized with username "profile-user-verifier-1" and password "profile-user-verifier-1-pwd"
    And  "USER_NUMS" users request to create a vc and verify it "VC_URL" with profiles issuer "ISSUER_PROFILE_ID" verify "VERIFY_PROFILE_ID" using "CONCURRENT_REQ" concurrent requests
