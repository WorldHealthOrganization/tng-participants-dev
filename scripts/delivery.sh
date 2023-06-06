mkdir temp
echo $1 > temp/config.json
sed -i "s/'/\"/g" temp/config.json
python scripts/config.py $2
python scripts/repo.py 
./scripts/verify.sh 1> /dev/null
python scripts/onboardingRequest.py
