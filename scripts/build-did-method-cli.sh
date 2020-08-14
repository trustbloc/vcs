#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Clones and builds the trustbloc did method CLI

PWD=`pwd`

mkdir -p build/did-method-cli
cd build/did-method-cli

if [ ! -d ./trustbloc-did-method/.git ]; then
  git clone -q https://github.com/trustbloc/trustbloc-did-method.git
fi

cd trustbloc-did-method
git checkout 37833f64df0f84e4f0dbc7a83b072819a881430c

make did-method-cli

cd ..

if [ ! -h cli ]; then
  ln -s trustbloc-did-method/.build/bin/cli cli
fi

cd $PWD
