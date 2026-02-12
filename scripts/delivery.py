import os
import json
import sys
import pycountry

def add_country(db, **params):
    print(f"[INFO] Adding test country: {params.get('alpha_3')} ({params.get('alpha_2')})")
    if not db._is_loaded:
        print("[INFO] Loading pycountry database...")
        db._load()

    obj = db.data_class(**params)
    db.objects.append(obj)

    for key, value in params.items():
        value = value.lower()
        if key in db.no_index:
            continue
        index = db.indices.setdefault(key, {})
        index[value] = obj

if __name__=='__main__':

    print("=== Starting onboarding script ===")

    # Load JSON
    print("[INFO] Loading scripts/countries.json...")
    try:
        with open('scripts/countries.json', 'r') as file:
            doc = json.load(file)
        print("[SUCCESS] countries.json loaded successfully.")
    except FileNotFoundError:
        print("[ERROR] 'countries.json' file not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print("[ERROR] Invalid JSON in 'countries.json'.", file=sys.stderr)
        sys.exit(1)

    # Add test countries
    print("[INFO] Adding virtual test countries...")

    # your add_country list unchanged

    countries = list(pycountry.countries)
    print(f"[INFO] Total countries in memory: {len(countries)}")

    # Fetch branches
    print("[INFO] Fetching existing git branches...")
    branches = os.popen("git ls-remote --heads").read()
    print("[INFO] Branch list fetched successfully.")

    print("Branches found:")
    print(branches)

    for country in countries:
        cCode = country.alpha_2
        if country.alpha_3 in doc:
            cCode = country.alpha_3

        print(f"\n=== Processing country: {country.alpha_3} ({country.alpha_2}) ===")

        if cCode not in doc:
            print(f"[INFO] Skipping {country.alpha_3} – no config found in JSON.")
            continue

        try:
            branchName = country.alpha_3 + "/onboardingRequest"
            print(f"[INFO] Checking if branch exists: {branchName}")

            if branchName not in branches:
                print(f"[INFO] Creating onboarding request for {country.alpha_3}")

                # Prepare folders
                print("[INFO] Cleaning old directories...")
                os.system("rm -rf repo")
                os.system("rm -rf temp")

                print("[INFO] Creating temp directory...")
                os.system("mkdir temp")

                print("[INFO] Writing country code and base64 data...")
                os.system("echo '"+country.alpha_3 + "\n' > temp/country")
                os.system("echo '"+doc[cCode]+ "' > temp/base64")

                print("[INFO] Running config.py...")
                if os.system("python scripts/config.py") != 0:
                    print("[ERROR] config.py failed.")
                    raise Exception("Configuration Error")

                tt_api_access = cCode + "_TT_API_ACCESS"
                if tt_api_access in doc:
                    print("[INFO] TT_API_ACCESS flag detected. Creating file.")
                    os.system("touch TT_API_ACCESS")

                if os.path.exists("sync"):
                    print("[INFO] Running Transitive Trust process...")
                    os.system("./scripts/transitiveTrust.sh "+country.alpha_2)

                    print("[INFO] Executing onboardingRequest.py with TT path...")
                    if os.system(
                        "python scripts/onboardingRequest.py ./transit/"+os.environ.get("ENV")+"/countries/"+country.alpha_2
                    ) != 0:
                        print("[ERROR] Onboarding Request failed under Transitive Trust.")
                        raise Exception("Onboarding Request failed.")
                else:
                    print("[INFO] Running standard flow (no Transitive Trust)")

                    print("[INFO] Cloning repo...")
                    if os.system("python scripts/repo.py") != 0:
                        raise Exception("Repository Cloning failed.")

                    print("[INFO] Running verify.sh...")
                    os.system("./scripts/verify.sh > /dev/null")

                    print("[INFO] Executing onboardingRequest.py...")
                    if os.system("python scripts/onboardingRequest.py repo") != 0:
                        raise Exception("Onboarding Request failed.")

                print("[INFO] Creating PR...")
                os.system("./scripts/createPR.sh "+country.alpha_3)

                print("[INFO] Resetting git workspace...")
                os.system("git checkout main > /dev/null 2>&1")
                os.system("git reset --hard && git clean -f -d > /dev/null 2>&1")

            else:
                print(f"[INFO] Skipping {country.alpha_3} – branch already exists. Please merge or delete it.")

        except Exception as Error:
            print(f"[ERROR] Error occurred for onboarding {country.alpha_3}: {Error}")
            continue

    print("\n=== Script completed ===")