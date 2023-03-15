#
# Copyright Avast Software. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@oidc4vc_stress
Feature: OIDC4VC issuance and VP stress test
  Scenario: issuance with pre-auth code flow and vp sharing
    Given number of users "USERS_NUM" making "CONCURRENT_REQ" concurrent requests
    When stress test is done
    Then metrics are collected and displayed
