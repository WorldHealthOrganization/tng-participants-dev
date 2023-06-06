mkdir temp
echo $1 > temp/base64
python scripts/config.py $2
python scripts/repo.py 
./scripts/verify.sh 1> /dev/null
python scripts/onboardingRequest.py
