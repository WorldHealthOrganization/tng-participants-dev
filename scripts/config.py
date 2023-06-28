import os
import json
import base64

with open("temp/base64") as f:
    decodedBytes = base64.urlsafe_b64decode(f.read())
    decodedStr = str(decodedBytes, "utf-8")
d = json.loads(decodedStr, strict=False)

if "sync" in d and d["sync"] == True:
    os.system("touch sync")
else:
    os.system("echo 'https://"+os.environ.get("GITHUB_TOKEN")+"@"+d["repo"] + "' > temp/repo")
    for key in d["keys"]:          
        os.system("echo '"+key + "' >> temp/gpg")