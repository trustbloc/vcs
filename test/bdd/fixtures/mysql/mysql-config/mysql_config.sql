/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

\! echo "Configuring MySQL users...";

/*
RP Adapter
*/
CREATE USER 'vcs'@'%' IDENTIFIED BY 'vcs-secret-pw';
GRANT ALL PRIVILEGES ON * . * TO 'vcs'@'%';


