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

# Demo

if __name__=='__main__':
        
    doc = json.loads(os.environ.get("SECRETS"), strict=False)
    
    add_country(pycountry.countries, alpha_2='XA', alpha_3='XXA', common_name='Test XA', 
                                     flag='😄', name='Test XA', numeric='23233', official_name='Test Country XA' ) 
    add_country(pycountry.countries, alpha_2='XB', alpha_3='XXB', common_name='Test XA', 
                                     flag='😄', name='Test XXB', numeric='2929', official_name='Test Country XB' )
    add_country(pycountry.countries, alpha_2='XY', alpha_3='XXY', common_name='Test XY', 
                                     flag='😄', name='Test XY', numeric='9989', official_name='Test Country XY' )
    add_country(pycountry.countries, alpha_2='XX', alpha_3='XXX', common_name='Test XA', 
                                     flag='😄', name='Test XX', numeric='9990', official_name='Test Country XX' )
    countries = list(pycountry.countries)

    for country in countries:        
        cCode = country.alpha_2
        if country.alpha_3 in doc:
            cCode= country.alpha_3
        if cCode in doc: 
            print("Try onboarding for " + country.alpha_3)
            try:
                os.system("rm -rf repo")
                os.system("rm -rf temp")
                os.system("mkdir temp")
                os.system("echo '"+country.alpha_3 + "\n' > temp/country")
                os.system("echo '"+doc[cCode]+ "' > temp/base64")
                os.system("python scripts/config.py")
                os.system("python scripts/repo.py")
                os.system("./scripts/verify.sh 1> /dev/null")
                os.system("python scripts/onboardingRequest.py")
                os.system("gh pr create -B main -H " + country.alpha_3 +"/onboardingRequest --title 'Bot requested a change for "+country.alpha_3+".' --body 'Please merge the onnboarding request of "+country.alpha_3+".'")
                os.system("git checkout main")
                os.system("git reset --hard && git clean -f -d")
            except Exception as Error:
                print("Error occoured for onboarding " + country.alpha_3 +": "+ Error)