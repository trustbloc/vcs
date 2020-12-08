#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


# Release Parameters
BASE_VERSION=0.1.5
IS_RELEASE=true

# Project Parameters
SOURCE_REPO=edge-service
BASE_VC_PKG_NAME=vc-rest
BASE_DID_PKG_NAME=did-rest
RELEASE_REPO=docker.pkg.github.com/trustbloc/${SOURCE_REPO}
SNAPSHOT_REPO=docker.pkg.github.com/trustbloc-cicd/snapshot

if [ ${IS_RELEASE} = false ]
then
  EXTRA_VERSION=snapshot-$(git rev-parse --short=7 HEAD)
  PROJECT_VERSION=${BASE_VERSION}-${EXTRA_VERSION}
  PROJECT_PKG_REPO=${SNAPSHOT_REPO}
else
  PROJECT_VERSION=${BASE_VERSION}
  PROJECT_PKG_REPO=${RELEASE_REPO}
fi

export VC_REST_TAG=$PROJECT_VERSION
export DID_REST_TAG=$PROJECT_VERSION
export VC_REST_PKG=${PROJECT_PKG_REPO}/${BASE_VC_PKG_NAME}
export DID_REST_PKG=${PROJECT_PKG_REPO}/${BASE_DID_PKG_NAME}
