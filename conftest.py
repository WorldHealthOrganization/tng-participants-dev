import os
import json
import pytest
import warnings
import pycountry
from glob import glob
from cryptography import x509
from functools import lru_cache

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

def pytest_addoption(parser):
    parser.addoption("-C", "--country-code", action="store", default="*", help="Country code of tests to run.")
    parser.addoption("-G", "--group", default=None, help="Certificate group (TLS,UP,SCA)")

@lru_cache(maxsize=16)
def _glob_files(country_code='*', base_dir='.'):
    "Find matching files"

    if country_code in ('*', None): 
        country_dirs = glob(os.path.join(base_dir,'???')) 
    else:
        country_dirs = [os.path.join(base_dir,country_code)]

    found_files = []
    for country_dir in country_dirs:
        for root, dirs, files in os.walk(country_dir):
            for file in files: 
                name, ext = os.path.splitext(file)
                if ext.lower() in ['.pem']:
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

    try:
        test_countries = json.load(open('testing_countries.json'))
        for country_def in test_countries.get('countries'):
            _add_country(pycountry.countries, **country_def)
    except Exception as ex:
        message = f"Testing countries could not be loaded ({str(ex)})"
        warnings.warn(message)

        
    def filter_filenames_by_group(files, group):
        if group is None: 
            return files
    
        if group.lower() in ('up', 'upload'): 
            return [ file for file in files if file.split(os.sep)[-2].lower() == 'up']
        if group.lower() in ('auth', 'tls'): 
            return [ file for file in files if file.split(os.sep)[-2].lower() == 'tls']
        if group.lower() in ('ca', 'csca', 'sca'): 
            return [ file for file in files if file.split(os.sep)[-2].lower() == 'sca']
        
        return files

    pem_files, country_folders = _glob_files( metafunc.config.getoption("country_code") )
    pem_files = filter_filenames_by_group(pem_files,metafunc.config.getoption("group") )

    # Parametrize all tests that have a "cert" parameter with the found cert files
    if "cert" in metafunc.fixturenames:
        #print(dir(metafunc))
        #print(metafunc.function)
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

