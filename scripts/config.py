import os
import json
import sys

with open("temp/config.json") as f:
    d = json.load(f, strict=False)
os.system("echo '"+d["country"] + "\n' > temp/country")
os.system("echo 'https://"+sys.argv[1]+"@"+d["repo"] + "' > temp/repo")
for key in d["keys"]:          
    os.system("echo '"+key + "' >> temp/gpg")
os.system("cat temp/gpg")
