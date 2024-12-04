import os
import json
import sys
import pycountry

def add_country(db, **params):
    '''Add a country to a pycountry database for the duration of this session. 
       This is useful to patch testing countries into a list of countries.''' 
    if not db._is_loaded:
        db._load()
    # Create an instance of the virtual country
    obj = db.data_class(**params)
    # Add it to the database
    db.objects.append(obj)
    # Update the indices
    for key, value in params.items():
        value = value.lower()
        if key in db.no_index:
            continue
        index = db.indices.setdefault(key, {})
        index[value] = obj

if __name__ == '__main__':
    try:
        # Read secrets from the 'countries_raw.json' file
        with open('scripts/countries_raw.json', 'r') as file:
            doc = json.load(file)
        print("Successfully loaded countries_raw.json.")
    except FileNotFoundError:
        print("Error: 'countries_raw.json' file not found.", file=sys.stderr)
        sys.exit(1)  # Exit with error code 1
    except json.JSONDecodeError:
        print("Error: 'countries_raw.json' contains invalid JSON.", file=sys.stderr)
        sys.exit(1)  # Exit with error code 1

    # Add custom test countries to pycountry
    add_country(pycountry.countries, alpha_2='XA', alpha_3='XXA', common_name='Test XA', 
                flag='😄', name='Test XA', numeric='23233', official_name='Test Country XA') 
    add_country(pycountry.countries, alpha_2='XB', alpha_3='XXB', common_name='Test XB', 
                flag='😄', name='Test XB', numeric='2929', official_name='Test Country XB')
    # (Other test countries omitted for brevity...)

    # List all branches
    branches = os.popen("git ls-remote --heads").read()
    print("Branches found:")
    print(branches)

    # Process each country
    countries = list(pycountry.countries)
    for country in countries:
        cCode = country.alpha_2
        if country.alpha_3 in doc:
            cCode = country.alpha_3
        if cCode in doc:
            try:
                branchName = f"{country.alpha_3}/onboardingRequest"
                if branchName not in branches:
                    os.system(f"echo Try onboarding for {country.alpha_3}")
                    # Prepare internal structure and execute scripts
                    os.system("rm -rf repo temp")
                    os.system("mkdir temp")
                    os.system(f"echo '{country.alpha_3}\n' > temp/country")
                    os.system(f"echo '{doc[cCode]}' > temp/base64")
                    if os.system("python scripts/config.py") != 0:
                        raise Exception("Configuration Error")
                    
                    # Transitive Trust API Access
                    tt_api_access = f"{cCode}_TT_API_ACCESS"
                    if tt_api_access in doc:
                        os.system("touch TT_API_ACCESS")
                    if os.path.exists("sync"):
                        os.system(f"./scripts/transitiveTrust.sh {country.alpha_2}")
                        if os.system(f"python scripts/onboardingRequest.py ./transit/{os.environ.get('ENV')}/countries/{country.alpha_2}") != 0:
                            raise Exception("Onboarding Request failed.")
                    else:
                        try:
                            if os.system("python scripts/repo.py") != 0:
                                raise Exception("Repository Cloning failed.")
                            os.system("./scripts/verify.sh 1> /dev/null")
                            if os.system("python scripts/onboardingRequest.py repo") != 0:
                                raise Exception("Onboarding Request failed.")
                        except Exception as Error:
                            os.system(f"echo 'Error occurred for onboarding request {country.alpha_3}: {Error}'")
                    os.system(f"./scripts/createPR.sh {country.alpha_3}")
                    os.system("git checkout main > /dev/null 2>&1")
                    os.system("git reset --hard && git clean -f -d > /dev/null 2>&1")
                else:
                    os.system(f"echo Skip {country.alpha_3} Branch already exists. Merge or delete the branch.")
            except Exception as Error:
                os.system(f"echo 'Error occurred for onboarding {country.alpha_3}: {Error}'")
