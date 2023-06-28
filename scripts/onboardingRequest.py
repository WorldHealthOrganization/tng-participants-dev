import os
from datetime import datetime

from datetime import datetime

date_time = datetime.now()

with open('temp/verifyResult') as f:
  result = f.readline()
  
  if not result:
      raise Exception("Bad verification.")
  else:
      print("Verification was good.")

with open('temp/country') as f:
  country = f.readline().replace("\n","")
  
branchName = country+"/onboardingRequest" 

os.system("git checkout -b" + branchName)
os.system("rm -rf "+ country)
os.system("mkdir " + country)
os.system("mv  -v repo/onboarding " + country + "/" )
os.system("mv " + country + "/onboarding/auth "+ country+"/onboarding/TLS")
os.system("mv " + country + "/onboarding/csca "+ country+"/onboarding/SCA")
os.system("mv " + country + "/onboarding/up "+ country+"/onboarding/UP")
os.system("mv " + country + "/onboarding/SCA/CSCA.pem "+ country+"/onboarding/SCA/SCA.pem")
os.system("git add "+ country)
os.system("git commit -m 'Bot added Files from "+country+"'")
os.system("git push -f -u origin "+ branchName)
