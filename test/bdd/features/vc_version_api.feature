#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_status_api
Feature: Version API

  Scenario: Request version
    When I request Version
    Then Version is set

  Scenario: Request SystemVersion
    When I request SystemVersion
    Then Version is set