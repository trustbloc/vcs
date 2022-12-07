#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e



cd /opt/workspace/vcs

echo "Building wallet cli binaries"

cd component/wallet-cli/;CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o ../../.build/dist/bin/wallet-cli-linux-amd64 main.go
cd /opt/workspace/vcs
cd .build/dist/bin;tar cvzf wallet-cli-linux-amd64.tar.gz wallet-cli-linux-amd64;rm -rf wallet-cli-linux-amd64
cd /opt/workspace/vcs

cd component/wallet-cli/;CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -o ../../.build/dist/bin/wallet-cli-linux-arm64 main.go
cd /opt/workspace/vcs
cd .build/dist/bin;tar cvzf wallet-cli-linux-arm64.tar.gz wallet-cli-linux-arm64;rm -rf wallet-cli-linux-arm64
cd /opt/workspace/vcs

cd component/wallet-cli/;GOOS=darwin GOARCH=arm64 go build -o ../../.build/dist/bin/wallet-cli-darwin-arm64 main.go
cd /opt/workspace/vcs
cd .build/dist/bin;tar cvzf wallet-cli-darwin-arm64.tar.gz wallet-cli-darwin-arm64;rm -rf wallet-cli-darwin-arm64
cd /opt/workspace/vcs

cd component/wallet-cli/;CC=o64-clang CXX=o64-clang++ CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o ../../.build/dist/bin/wallet-cli-darwin-amd64 main.go
cd /opt/workspace/vcs
cd .build/dist/bin;tar cvzf wallet-cli-darwin-amd64.tar.gz wallet-cli-darwin-amd64;rm -rf wallet-cli-darwin-amd64
cd /opt/workspace/vcs
