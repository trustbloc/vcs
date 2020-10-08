#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Generates the well-known-server config files for the discovery service in BDD tests

function convert_file_linux() {
  # base64url encode payload: base64 -w 0 | sed 's/+/-/g; s/\//_/g'
  # then embed in a dummy jws and write to the config folder
  # $1: file name
  echo "{\"payload\":\"$(cat $1 | base64 -w 0 | sed 's/+/-/g; s/\//_/g; s/=//g')\",\"signatures\":[{\"header\":{\"kid\":\"\"},\"signature\":\"\"}]}" > ../config/$1
}

function convert_file_osx() {
  # base64url encode payload: base64 | sed 's/+/-/g; s/\//_/g'
  # then embed in a dummy jws and write to the config folder
  # $1: file name
  echo "{\"payload\":\"$(cat $1 | base64 | sed 's/+/-/g; s/\//_/g; s/=//g')\",\"signatures\":[{\"header\":{\"kid\":\"\"},\"signature\":\"\"}]}" > ../config/$1
}

pwd=`pwd`

configs=( test/bdd/fixtures/stakeholder-server test/bdd/fixtures/discovery-server )

# processes config data files using provided function, to generate config files for bdd tests
function process_files() {
  # $1: function with which to process files

  for conf_folder in "${configs[@]}"; do
    rm -rf $conf_folder/config
    mkdir -p $conf_folder/config
    cd $conf_folder/config-data

    for f in *; do
      # Invoke processing function on file
      $1 $f
    done

    cd $pwd
  done
}

if [[ "$OSTYPE" == "linux-gnu" ]]; then
  process_files convert_file_linux
elif [[ "$OSTYPE" == "darwin"* ]]; then
  process_files convert_file_osx
fi
