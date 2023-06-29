export GITHUB_TOKEN=$BOT_TOKEN_GITHUB

gh pr create -B main -H onboardingRequest/$1 --title 'Bot requested a change for '$1'.' --body 'Please merge the onnboarding request of '$1'.' > /dev/null 2>&1
                
