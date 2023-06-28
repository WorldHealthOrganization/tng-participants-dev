echo $BOT_TOKEN_GITHUB > token
gh auth login --with-token < token
rm token

gh pr create -B main -H $1/onboardingRequest --title 'Bot requested a change for $1' --body 'Please merge the onnboarding request of $1.' > /dev/null 2>&1
                
gh auth logout -h github.com