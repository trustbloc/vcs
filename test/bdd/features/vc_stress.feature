#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@vc_stress
Feature: VC stress test
  @vc_stress_test
  Scenario: Stress test method
    When "ACCESS_TOKEN_URL" Organization "ORG_ID" has been authorized with client id "CLIENT_ID" and secret "SECRET"
    And  "USER_NUMS" users request to create a vc and verify it "VC_URL" with profiles issuer "ISSUER_PROFILE_ID" verify "VERIFY_PROFILE_ID" and org id "ORG_ID" using "CONCURRENT_REQ" concurrent requests
