#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@log_api
Feature: Change log levels
  Scenario Outline: Modify log levels
    When an HTTP POST is sent to "http://localhost:8075/loglevels" with content "DEBUG" of type "text/plain"
    When an HTTP POST is sent to "http://localhost:8075/loglevels" with content "INVALID" of type "text/plain" and the returned status code is 500

