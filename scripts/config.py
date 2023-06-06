import os
import json
import sys
import base64

with open("temp/base64") as f:
    decodedBytes = base64.urlsafe_b64decode(f.read())
    decodedStr = str(decodedBytes,"utf-8")
d = json.loads(decodedStr, strict=False)
os.system("echo '"+d["country"] + "\n' > temp/country")
os.system("echo 'https://"+sys.argv[1]+"@"+d["repo"] + "' > temp/repo")
for key in d["keys"]:          
    os.system("echo '"+key + "' >> temp/gpg")
