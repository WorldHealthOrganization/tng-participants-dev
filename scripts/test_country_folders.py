import pytest
import os

def test_folder_structure(country_folder): 
    # Create a dict of tuples for all found files:
    # The key is the domain (DCC, ICAO, etc.)
    # Each tuple contains the path starting from the domain folder, 
    # e.g. ('TLS','TLS.pem')

    # This makes the subsequent code independent from the OS path separator

    # Collect the files before testing
    
    onboardings = {}
    for path, dirs, files in os.walk(country_folder):
        for file in files: 
            long_path = tuple(os.path.join(path, file).split(os.sep)[2:])
            if long_path[0].lower() == 'onboarding':
                domain = long_path[1]
                if not domain in onboardings:
                    onboardings[domain] = []
                onboardings[domain].append(long_path[2:])

    # Testing folder structure
    for domain in onboardings.keys():
        assert domain in ('DCC','DDCC','DIVOC','ICAO','SHC'), 'Invalid domain: '+domain

        assert ('TLS', 'TLS.pem') in onboardings[domain], f'TLS cert is missing in domain {domain}'
        assert ('UP', 'UP.pem') in onboardings[domain], f'UP cert is missing in domain {domain}'
        assert ('SCA', 'SCA.pem') in onboardings[domain], f'SCA cert is missing in domain {domain}'

    
