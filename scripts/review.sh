#!/bin/bash

export GITHUB_TOKEN=$GITHUB_JOB_TOKEN

gh pr status -c

if [ -e "temp/Failure" ]; then
  gh pr review $1/onboardingRequest -r -b "Please resolve the Errors before proceeding. The failure files contain more information." 
fi

if [ -e "temp/CSR" ]; then
  gh pr review $1/onboardingRequest -r -b "The CSRs needs to be signed before merging"
fi

if [ -e "temp/SIGNED" ]; then
  gh pr review $1/onboardingRequest -r -b "The content is currently not signed. Run the sign script before merging"
fi
