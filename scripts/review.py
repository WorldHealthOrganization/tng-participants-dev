import os
from pathlib import Path

prCommand = "gh pr view "+ os.environ("BRANCH") + " --json headRefName,comments,headRepositoryOwner,body,number,reviews,state,author"
branch = os.environ("BRANCH")[0:3]
result = os.popen(prCommand).read()

print(result)

# approve = True
# noFailure = True
# signedFolderPresent = True
# csrNotSigned = True
# csrNotPresent = True

# country = country_folder[0:3]
# print(country)
# pathlist = Path(country_folder+"/onboarding/UP").glob('**/Failure')

# if len(pathlist): 
#     approve &= False
#     noFailure &= False
    
# if not (os.path.exists(country_folder+"/onboarding/UP/signed") and os.path.exists(country_folder+"/onboarding/TLS/signed") and os.path.exists(country_folder+"/onboarding/SCA/signed") and os.path.exists(country_folder+"/onboarding/ISSUER/signed")):  
#     signedFolderPresent &= False
#     approve &= False
    
# if  os.path.exists(country_folder+"/onboarding/UP/UP_SYNC.CSR"):  
#     csrNotSigned &= False
#     approve &= False
    
# if  os.path.exists(country_folder+"/onboarding/UP/UP_SYNC.PEM") and os.path.exists(country_folder+"/onboarding/UP/UP_SYNC.CSR"):  
#     csrNotPresent &= False
#     approve &= False
    
# if not noFailure:
#     os.system("gh pr review "+country+"/onboardingRequest -r -b 'Folder contains Failure files. Please resolve it.'")
    
# if not signedFolderPresent:
#     os.system("gh pr review "+country+"/onboardingRequest -r -b 'Signed Folder not present.'")
    
# if not csrNotSigned: 
#     os.system("gh pr review "+country+"/onboardingRequest -r -b 'CSR is not signed for UP. Please sign it.'")
    
# if not csrNotPresent: 
#     os.system("gh pr review "+country+"/onboardingRequest -r -b 'CSR is still present, but already signed.'")
        
# if approve:
#     os.system("gh pr review "+country+"/onboardingRequest -a -b 'Everything fine.'")
