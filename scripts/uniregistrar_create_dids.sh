#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

ROOT=`pwd`
DRIVERS=driver-did-v1,driver-did-sov

echo "starting universal registrar"
cd $ROOT/test/bdd/fixtures/universal-registrar
docker-compose down --remove-orphans
docker-compose pull && docker-compose up --force-recreate -d

until $(curl --output /dev/null --silent --head --fail $UNIREGISTRAR_LOCAL); do
    printf '.'
    sleep 3
done

cd $ROOT/.build
npm install axios
RegistrarLocalURL=${UNIREGISTRAR_LOCAL} RegistrarRemoteURL=${UNIREGISTRAR_REMOTE} DRIVERS=${DRIVERS} node ./uniregistrar-create-dids.js

echo "stopping universal registrar"
cd $ROOT/test/bdd/fixtures/universal-registrar
docker-compose down --remove-orphans
