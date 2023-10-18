#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

go generate ./...
pwd=`pwd`
touch "$pwd"/coverage.out

amend_coverage_file () {
if [ -f profile.out ]; then
    cat profile.out | grep -v ".gen.go" >> "$pwd"/coverage.out
    rm profile.out
fi
}

# Running vcs unit tests
echo "vcs unit tests..."
PKGS=`go list github.com/trustbloc/vcs/... 2> /dev/null | \
                                                  grep -v /mocks | \
                                                  grep -v /pkg/locker`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

# Running vcs unit tests
echo "locker tests..."
PKGS=`go list github.com/trustbloc/vcs/... 2> /dev/null | \
                                                  grep /pkg/locker`
go test $PKGS -count=1 -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

echo "... done"
echo "vc-rest unit tests..."
# Running vc-rest unit tests
cd cmd/vc-rest
PKGS=`go list github.com/trustbloc/vcs/cmd/vc-rest/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd"

# Running event unit tests
echo "... done"
echo "event unit tests..."
cd component/event
PKGS=`go list github.com/trustbloc/vcs/component/event/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd"

# Running credentialstatus component unit tests
echo "... done"
echo "credentialstatus unit tests..."
cd component/credentialstatus
go generate ./...
PKGS=`go list github.com/trustbloc/vcs/component/credentialstatus/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd"

# Running otp component unit tests
echo "... done"
echo "otp unit tests..."
cd component/otp
PKGS=`go list github.com/trustbloc/vcs/component/otp/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd"

# Running oidc fosite mongo unit tests
echo "... done"
echo "oidc fosite mongo unit tests..."
cd component/oidc/fosite/mongo
PKGS=`go list github.com/trustbloc/vcs/component/oidc/fosite/mongo... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd"

# Running oidc fosite redis unit tests
echo "... done"
echo "oidc fosite redis unit tests..."
cd component/oidc/fosite/redis
PKGS=`go list github.com/trustbloc/vcs/component/oidc/fosite/redis... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd"

# Running oidc vp unit tests
echo "... done"
echo "oidc vp unit tests..."
cd component/oidc/vp
PKGS=`go list github.com/trustbloc/vcs/component/oidc/vp... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd"

# Running healthchecks component unit tests
echo "... done"
echo "healthchecks unit tests..."
cd component/healthchecks
PKGS=`go list github.com/trustbloc/vcs/component/healthchecks/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd"

# Running profile reader component unit tests
echo "... done"
echo "profile reader unit tests..."
cd component/profile/reader/file
PKGS=`go list github.com/trustbloc/vcs/component/profile/reader/file/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd"

echo "... done all unit-tests"