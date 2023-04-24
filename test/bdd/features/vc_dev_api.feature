#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@vc_dev_api
Feature: Request DID Config

  Scenario Outline: Request DID Config
    When I request did config for "<profileType>" with ID "<profileId>" and type "<credentialType>"
    Then I receive response with status code "200" for didconfig

    Examples:
      | profileType | profileId                     | credentialType |
      | issuer      | i_myprofile_ud_P256k1/v1.0    | ldp            |
      | issuer      | i_myprofile_ud_es256_jwt/v1.0 | jwt            |
      | verifier    | v_myprofile_ldp/v1.0          | ldp            |
      | verifier    | v_myprofile_jwt/v1.0          | jwt            |
      | verifier    | v_myprofile_multivp_jwt/v1.0  | jwt            |