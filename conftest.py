import os
import json
import pytest
import warnings
import pycountry
from glob import glob
from cryptography import x509
from functools import lru_cache

def pytest_addoption(parser):
    parser.addoption("--country-mode", action="store_true", help="Expect country folders")
    parser.addoption("-G", "--group", default=None, help="Filter group (TLS,UP,SCA)")
    parser.addoption("-C", "--country", default=None, help="Filter by country")
    parser.addoption("-D", "--domain", default=None, help="Filter domain (DCC,DDCC,ICAO,...)")

_PATH_INDEX_FILENAME = -1
_PATH_INDEX_GROUP = -2
_PATH_INDEX_DOMAIN = -3
_PATH_INDEX_COUNTRY = -5

def _add_country(db, **params):
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

try:
    test_countries = json.load(open(os.path.join('scripts','tests','testing_countries.json')))
    for country_def in test_countries.get('countries'):
        _add_country(pycountry.countries, **country_def)
except Exception as ex:
    message = f"Testing countries could not be loaded ({str(ex)})"
    warnings.warn(message)


@lru_cache(maxsize=16)
def _glob_files(country_mode=False, base_dir='.' ):
    if country_mode: 
        country_dirs = glob(os.path.join(base_dir,'???')) 
    else:
        country_dirs = [os.path.join(base_dir,'onboarding')]        

    found_files = []
    for country_dir in country_dirs:
        for root, dirs, files in os.walk(country_dir):
            for file in files: 
                name, ext = os.path.splitext(file)
                if ext.lower() in ['.pem', '.crt']:
                    found_files.append(os.path.join(root, file))

    return found_files, country_dirs

def pytest_generate_tests(metafunc):
    ''' Walk all subfolders of the current directory that consist of 3 characters
        XOR walk the directory that has been specified in the --country-code parameter
        of the test run. 
        
        Generate a test execution matrix
            - All test cases that have a "pem_file" parameter
            - All pem files discovered in the directory walk
    ''' 

    def filter_by(pem_files, filter_value, filter_index):
       if not filter_value:
           return pem_files
       return [p for p in pem_files if p.split(os.sep)[filter_index].upper()\
                                         == filter_value.upper() ]
    
    config = metafunc.config
    pem_files, country_folders = _glob_files( config.getoption('country_mode') )
    if config.getoption('country') and not config.getoption('country_mode'):
        raise ValueError('Country filter cannot be applied if not running in country-mode.'+
                         ' Use --country-mode to enable this mode.')

    pem_files = filter_by(pem_files, config.getoption('group'), _PATH_INDEX_GROUP )
    pem_files = filter_by(pem_files, config.getoption('country'), _PATH_INDEX_COUNTRY )
    pem_files = filter_by(pem_files, config.getoption('domain'), _PATH_INDEX_DOMAIN )

    country_folders = filter_by(country_folders, config.getoption('country'), 1 )

    # Parametrize all tests that have a "cert" parameter with the found cert files
    if "cert" in metafunc.fixturenames:
        metafunc.parametrize("cert", pem_files, indirect=True)

    # Parametrize all tests that have a "country" parameter with the found dirs
    if "country_folder" in metafunc.fixturenames:
        metafunc.parametrize("country_folder", country_folders, indirect=True)

_cert_cache = {}
@pytest.fixture
def cert(request):
    "the pem file that should be tested"
    if not request.param in _cert_cache:
        _cert_cache[request.param] = PemFileWrapper(request.param)
    return _cert_cache[request.param]

@pytest.fixture
def country_folder(request):
    return request.param


class PemFileWrapper:
    file_name = None
    error = None
    pathinfo = {}
    extensions = {}
    
    def __init__(self, pem_file):
        self.file_name = os.path.normpath(pem_file)
        try: 
            self.x509 = x509.load_pem_x509_certificate(
                open(self.file_name,'rb').read()
            )
        except Exception as ex: 
            self.error = ex
            self.x509 = None

        try:
            self.extensions = {}
            for ex in self.x509.extensions:
                self.extensions[ ex.oid.dotted_string ] = ex 
                if not ex.oid._name == 'Unknown OID':
                    self.extensions[ ex.oid._name ] = ex
        except:
            pass # Could not load extensions


        try: 
            self.pathinfo = {}
            path = self.file_name.split(os.sep)
            self.pathinfo['filename'] = path[-1] # CA.pem, TLS.pem, UP.pem ...
            self.pathinfo['group'] = path[-2] # up, csca, auth
            self.pathinfo['domain'] = path[-3] # DCC, DIVOC, SHC
            self.pathinfo['country'] = path[-5] # GER, BEL, FIN ...
        except:
            pass

