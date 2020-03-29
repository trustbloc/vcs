#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

ROOT=`pwd`
REGISTRAR_URL=http://localhost:9080
DRIVERS=driver-did-v1,driver-did-sov

echo "starting universal registrar"
cd $ROOT/test/bdd/fixtures/universal-registrar
docker-compose down --remove-orphans
docker-compose pull && docker-compose up --force-recreate -d

until $(curl --output /dev/null --silent --head --fail $REGISTRAR_URL); do
    printf '.'
    sleep 3
done

cd $ROOT/.build
npm install axios
ResolverURL=${REGISTRAR_URL} DRIVERS=${DRIVERS} node ./uniregistrar-create-dids.js

echo "stopping universal registrar"
cd $ROOT/test/bdd/fixtures/universal-registrar
docker-compose down --remove-orphans
