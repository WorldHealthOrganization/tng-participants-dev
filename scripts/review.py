import os
import glob
import json


def findComment(comment,comments):
    for c in comments:
        if c["body"] == comment:
            return True
    return False

prCommand = "gh pr view "+ os.environ.get("BRANCH") + " --json headRefName,comments,headRepositoryOwner,body,number,reviews,state,author,reviews"
country = os.environ.get("BRANCH")[0:3]
result = os.popen(prCommand).read()

pr = json.loads(result)

approve = True
noFailure = True
signedFolderPresent = True
csrNotSigned = True
csrNotPresent = True

files = glob.glob(country+"/**/Failure", recursive=True)
comments = pr["reviews"]

if len(files): 
    approve &= False
    noFailure &= False
    
if not (os.path.exists(country+"/onboarding/DCC/UP/signed") and os.path.exists(country+"/onboarding/DCC/TLS/signed") and os.path.exists(country+"/onboarding/DCC/SCA/signed")):  
    signedFolderPresent &= False
    approve &= False
    
if  os.path.exists(country+"/onboarding/DCC/UP/UP_SYNC.CSR"):  
    csrNotSigned &= False
    approve &= False
    
if  os.path.exists(country+"/onboarding/DCC/UP/UP_SYNC.PEM") and os.path.exists(country+"/onboarding/DCC/UP/UP_SYNC.CSR"):  
    csrNotPresent &= False
    approve &= False
    
if not noFailure:
    comment = "Folder contains Failure files. Please resolve it."
    if not findComment(comment,comments):
     os.system("gh pr review "+country+"/onboardingRequest -r -b '"+comment+"'")
    
if not signedFolderPresent:
    comment = "Signed Folder not present."
    if not findComment(comment,comments):
     os.system("gh pr review "+country+"/onboardingRequest -r -b '"+comment+"'")
    
if not csrNotSigned: 
    comment = "CSR is not signed for UP. Please sign it."
    if not findComment(comment,comments):
     os.system("gh pr review "+country+"/onboardingRequest -r -b '"+comment+"'")
    
if not csrNotPresent: 
    comment = "CSR is still present, but already signed."
    if not findComment(comment,comments):
     os.system("gh pr review "+country+"/onboardingRequest -r -b '"+comment+"'")
        
if approve:
    os.system("gh pr review "+country+"/onboardingRequest -a -b 'Everything fine.'")
