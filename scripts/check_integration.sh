#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

declare -a tests=(
   "holder_rest"
   "issuer_rest"
   "vc_rest"
   "w3c_workflow"
)

PWD=`pwd`
TAGS="${TAGS:all}"
cd test/bdd

totalAgents=${SYSTEM_TOTALJOBSINPHASE:-0}   # standard VSTS variables available using parallel execution; total number of parallel jobs running
agentNumber=${SYSTEM_JOBPOSITIONINPHASE:-0} # current job position
testCount=${#tests[@]}

# below conditions are used if parallel pipeline is not used. i.e. pipeline is running with single agent (no parallel configuration)
if [ "$agentNumber" -eq 0 ]; then agentNumber=1; fi

if [ "$totalAgents" -eq 0 ]; then
  echo "Running vc integration tests..."
  go test -count=1 -v -cover . -p 1 -timeout=40m
else
  if [ "$agentNumber" -gt $totalAgents ]; then
    echo "No more tests to run"
  else
    for ((i = "$agentNumber"; i <= "$testCount"; )); do
      testToRun=("${tests[$i - 1]}")
      echo "***** Running the following test: $testToRun"
      go test -count=1 -v -cover . -p 1 -timeout=30m -run $testToRun
      i=$((${i} + ${totalAgents}))
    done
    mv ./docker-compose.log "./docker-compose-$agentNumber.log"
  fi
fi

cd $PWD
