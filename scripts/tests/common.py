import functools
import pytest
import os 

def requires_readable_cert(func):
    'Decorator for tests that should be skipped if the cert has not been loaded'
    @functools.wraps(func)
    def wrapper(cert, *args, **kwargs):
        if not cert or cert.error: 
            pytest.skip(reason='Certificate could not be loaded')
        else: 
            return func(cert,*args, **kwargs)
    return wrapper

@functools.lru_cache(maxsize=128)
def collect_onboarding_files(country_folder):
    '''  Create a dict of tuples for all found files:
         The key is the domain (DCC, ICAO, etc.)
         Each tuple contains the path starting from the domain folder, 
            e.g. ('TLS','TLS.pem')
    '''
    offset = len(country_folder.split(os.sep))
    onboardings = {}
    for path, dirs, files in os.walk(country_folder):
        for file in files: 
            long_path = tuple(os.path.join(path, file).split(os.sep)[offset:])
            if long_path[0].lower() == 'onboarding':
                domain = long_path[1]
                if not domain in onboardings:
                    onboardings[domain] = []
                onboardings[domain].append(long_path[2:])
    return onboardings
