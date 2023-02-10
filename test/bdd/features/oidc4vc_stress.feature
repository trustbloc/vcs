#
# Copyright Avast Software. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@oidc4vc_stress
Feature: OIDC4VC issuance and VP stress test
  Scenario: issuance with pre-auth code flow and vp sharing
    Given number of users "USERS_NUM"
      And demo issuer URL "DEMO_ISSUER_URL"
      And demo verifier URL to get QR code "DEMO_VERIFIER_GET_QR_CODE_URL"
    When stress test is done
    Then metrics are collected and displayed
