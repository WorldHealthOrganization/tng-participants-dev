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
            try:
                os.system("echo Try onboarding for " + country.alpha_3)
                
                ###############  Transitive Trust
                
                os.system("git clone https://"+doc["BOT_TOKEN_GITHUB"]+"@"+os.environ.get("TRANSITIVE_TRUST_SOURCE") + " transit")
                os.system("cd transit")
                os.system("cd "+os.environ("ENV"))
                os.system("mkdir signing")
                os.system("cd signing") 
                os.system("echo "+doc["NB_UP_SIGNING_PUB"]+" > pub-key.pem")
                os.system("echo "+doc["NB_UP_SIGNING_KEY"]+" > priv-key.pem")
                os.system("cd ..")
                os.system("cd ..")
                os.system("./extract.sh "+ os.environ.get("ENV")+" "+country.alpha_2)     
                os.system("cd ..")
                
                ################## Prepare the internal structure
                os.system("rm -rf repo")
                os.system("rm -rf temp")
                os.system("mkdir temp")
                os.system("echo '"+country.alpha_3 + "\n' > temp/country")
                os.system("echo '"+doc[cCode]+ "' > temp/base64")
                if os.system("python scripts/config.py") !=0:
                    raise Exception("Configuration Error")
                
                if os.path.exists("sync"):  
                   if os.system("python scripts/onboardingRequest.py transit/"+country.alpha_2) != 0:
                          raise Exception("Onboarding Request failed.")
                else:
                    try:       
                        if os.system("python scripts/repo.py") != 0:
                              raise Exception("Repository Cloning failed.")
                          
                        os.system("./scripts/verify.sh 1> /dev/null")
                        
                        if os.system("python scripts/onboardingRequest.py repo") != 0:
                          raise Exception("Onboarding Request failed.")
                    except Exception as Error:
                        os.system("echo 'Error occoured for onboarding request " + country.alpha_3 +": "+str(Error)+"'") 
                    
                os.system("gh pr create -B main -H " + country.alpha_3 +"/onboardingRequest --title 'Bot requested a change for "+country.alpha_3+".' --body 'Please merge the onnboarding request of "+country.alpha_3+".' > /dev/null 2>&1" )
                
                if os.path.exists(country.alpha_3+"/onboarding/UP"):
                 os.system("./scripts/fileCheck.sh "+country.alpha_3+"/onboarding/UP")
                if os.path.exists(country.alpha_3+"/onboarding/TLS"):
                 os.system("./scripts/fileCheck.sh "+country.alpha_3+"/onboarding/TLS")
                if os.path.exists(country.alpha_3+"/onboarding/SCA"):
                  os.system("./scripts/fileCheck.sh "+country.alpha_3+"/onboarding/SCA")
                if os.path.exists(country.alpha_3+"/onboarding/ISSUER"):
                 os.system("./scripts/fileCheck.sh "+country.alpha_3+"/onboarding/ISSUER")
                
                if os.path.exists("temp/Failure"):
                    os.system("gh pr review "+country.alpha_3 +"/onboardingRequest -r -c 'The PR contains Failure files which must be resolved'. -b 'Please resolve the Errors before proceeding. The failure files contain more information.'")
                
                if os.path.exists("temp/CSR"):
                    os.system("gh pr review "+country.alpha_3 +"/onboardingRequest -r -c 'Please resolve the CSR signings before merging.' -b 'The CSRs needs to be signed before merging'")
                
                if os.path.exists("temp/SIGNED"):
                        os.system("gh pr review "+country.alpha_3 +"/onboardingRequest -r -c 'Please signed the content before merging' -b 'The content is currently not signed. Run the sign script before merging'")
                   
                os.system("git checkout main > /dev/null 2>&1")
                os.system("git reset --hard && git clean -f -d > /dev/null 2>&1")
            except Exception as Error:
                os.system("echo 'Error occoured for onboarding " + country.alpha_3 +": "+ str(Error)+"'")