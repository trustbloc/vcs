#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

pwd=`pwd`


MODELS_PATH="${MODELS_PATH}"
CLIENT_PATH="${CLIENT_PATH}"
SPEC_LOC="$PWD/${SPEC_LOC}"
IMAGE="${DOCKER_IMAGE:-quay.io/goswagger/swagger}"
IMAGE_VERSION="${DOCKER_IMAGE_VERSION:-latest}"

rm -rf $MODELS_PATH/models
rm -rf $CLIENT_PATH/client
rm -rf $CLIENT_PATH/models

cd $MODELS_PATH

# generate and validate commands
GENERATE_MODELS_COMMAND="generate model --spec=$SPEC_LOC"
GENERATE_CLIENT_COMMAND="generate client -f $SPEC_LOC"

echo "Generating models"
docker run --rm -v $HOME:$HOME -w $(pwd) ${IMAGE}:${IMAGE_VERSION} $GENERATE_MODELS_COMMAND

cd "$pwd"

cd $CLIENT_PATH

echo "Generating client"
docker run --rm -v $HOME:$HOME -w $(pwd) ${IMAGE}:${IMAGE_VERSION} $GENERATE_CLIENT_COMMAND
