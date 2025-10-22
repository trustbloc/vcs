#!/bin/bash

function generate_krakend_config() {
  env=$1

  build_path="build/$env"

  mkdir -p "$build_path"

  docker run --rm -v "$PWD":/etc/krakend/ \
  -e FC_ENABLE=1 \
  -e FC_OUT="/etc/krakend/$build_path/krakend-raw.json" \
  -e FC_PARTIALS="/etc/krakend/partials" \
  -e FC_SETTINGS="/etc/krakend/settings" \
  -e FC_TEMPLATES="/etc/krakend/templates" \
  krakend check -d -t -c /etc/krakend/krakend.tmpl

  if [ -x "$(command -v jq)" ]
  then
      jq '.' ./"$build_path"/krakend-raw.json > ./"$build_path"/krakend-formatted.json
  else
    echo "jq could not be found"
  fi
}

generate_krakend_config local
