import os
import glob
import json
import time
import sys

# Usage folders that are not signed by scripts/signing/sign-json.sh and therefore
# must NOT be required to contain a 'signed/' subfolder (e.g. DDCC/REFERENCES only
# holds Trusted_Reference.json, which is a reference list, not a signed artifact).
SIGN_EXEMPT_USAGES = {"REFERENCES"}

# Check-run status values (from `gh pr checks --json`) that indicate a real failure.
FAILED_CHECK_STATES = {"fail", "failure", "cancel", "cancelled", "timed_out", "action_required", "startup_failure"}

def check_signed_folder_exists(base_dir):
    # Reference-type folders are not signed by design, so treat them as satisfied.
    if os.path.basename(os.path.normpath(base_dir)) in SIGN_EXEMPT_USAGES:
        print("skip (sign-exempt): " + base_dir)
        return True
    signed_folder_path = os.path.join(base_dir, 'signed')
    print("search for: " + signed_folder_path)
    return os.path.isdir(signed_folder_path)

def check_all_directories(base_pattern):
    directories = glob.glob(base_pattern)
    for dir_name in directories:
        if not check_signed_folder_exists(dir_name):
            print("Does not exist!")
            return False
    print("Exist!")
    return True

def evaluate_checks(branch, exclude_names=("transitive-trust-failure-check",)):
    '''Evaluate PR check runs using structured JSON instead of substring matching.

       Returns True only if no relevant check is in a failed state. The review
       bot's own job is excluded to avoid self-reference, and the
       check *name* is never used to decide pass/fail (only the status/bucket),
       so names like "transitive-trust-failure-check" cannot cause false fails.
    '''
    while True:
        raw = os.popen("gh pr checks " + branch + " --json name,state,bucket").read()
        try:
            checks = json.loads(raw) if raw.strip() else []
        except json.JSONDecodeError:
            print("Could not parse checks JSON, retrying...")
            time.sleep(5)
            continue

        relevant = [c for c in checks if c.get("name") not in exclude_names]
        states = {(c.get("bucket") or c.get("state") or "").lower() for c in relevant}
        print("Check states: " + str(states))

        if "pending" in states:
            time.sleep(5)
            continue

        return not (FAILED_CHECK_STATES & states)

#   additions
#   assignees
#   author
#   autoMergeRequest
#   baseRefName
#   body
#   changedFiles
#   closed
#   closedAt
#   comments
#   commits
#   createdAt
#   deletions
#   files
#   headRefName
#   headRefOid
#   headRepository
#   headRepositoryOwner
#   id
#   isCrossRepository
#   isDraft
#   labels
#   latestReviews
#   maintainerCanModify
#   mergeCommit
#   mergeStateStatus
#   mergeable
#   mergedAt
#   mergedBy
#   milestone
#   number
#   potentialMergeCommit
#   projectCards
#   projectItems
#   reactionGroups
#   reviewDecision
#   reviewRequests
#   reviews
#   state
#   statusCheckRollup
#   title
#   updatedAt
#   url

prCommand = "gh pr view "+ os.environ.get("BRANCH") + " --json headRefName,comments,headRepositoryOwner,body,number,reviews,state,author,reviews"
country = os.environ.get("BRANCH")[0:3]
result = os.popen(prCommand).read()

pr = json.loads(result)

checksStatus = "gh pr checks "+ os.environ.get("BRANCH")

repeat = True
checkRunSucceeded = True
approve = True

# Evaluate checks via structured JSON status (not raw substring matching), so
# that a job NAME containing "fail" (e.g. transitive-trust-failure-check) can no
# longer be misread as an actual test failure.
checkRunSucceeded = evaluate_checks(os.environ.get("BRANCH"))
if not checkRunSucceeded:
    approve = False

noFailure = True
signedFolderPresent = True
csrNotSigned = True
csrNotPresent = True

files = glob.glob(country+"/**/Failure", recursive=True)
reviews = pr["reviews"]

change_requested = pr["state"] == "CHANGE_REQUESTED"

if len(files): 
    approve &= False
    noFailure &= False
  
result = check_all_directories(country+"/onboarding/*/*")

if not (result):  
    signedFolderPresent &= False
    approve &= False
       
if not noFailure:
    comment = "Folder contains Failure files. Please resolve it."
    os.system("gh pr review "+country+sys.argv[1]+" -r -b '"+comment+"'")
    
if not signedFolderPresent:
    comment = "Signed Folder not present."
    os.system("gh pr review "+country+sys.argv[1]+" -r -b '"+comment+"'")

if not csrNotSigned: 
    comment = "CSR is not signed for UP. Please sign it."
    os.system("gh pr review "+country+sys.argv[1]+" -r -b '"+comment+"'")
    
if not csrNotPresent: 
    comment = "CSR is still present, but already signed."
    os.system("gh pr review "+country+sys.argv[1]+" -r -b '"+comment+"'")
    
if not checkRunSucceeded: 
    comment = "Tests Failed. Please resolve the issues."
    os.system("gh pr review "+country+sys.argv[1]+" -r -b '"+comment+"'")
        
if approve:
    comment = "Everything fine."
    os.system("gh pr review "+country+sys.argv[1]+" -a -b 'Everything fine.'")
