export GITHUB_TOKEN = $GITHUB_JOB_TOKEN

gh pr create -B main -H $1/onboardingRequest --title 'Bot requested a change for $1' --body 'Please merge the onnboarding request of $1.' > /dev/null 2>&1
                
