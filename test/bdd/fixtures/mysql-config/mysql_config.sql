/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

\! echo "Configuring MySQL users...";

/*
oidc provider (hydra)
*/
CREATE USER 'thirdpartyoidc'@'%' IDENTIFIED BY 'thirdpartyoidc-secret-pw';
CREATE DATABASE thirdpartyoidc;
GRANT ALL PRIVILEGES ON thirdpartyoidc.* TO 'thirdpartyoidc'@'%';
