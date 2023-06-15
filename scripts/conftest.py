import os
import pytest
import pycountry
from glob import glob
from cryptography import x509

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

    
def pytest_generate_tests(metafunc):
    ''' Walk all subfolders of the current directory that consist of 3 characters
        XOR walk the directory that has been specified in the --country-code parameter
        of the test run. 
        
        Generate a test execution matrix
            - All test cases that have a "pem_file" parameter
            - All pem files discovered in the directory walk
    ''' 
    _add_country(pycountry.countries, alpha_2='XA', alpha_3='XXA', common_name='Test XA',
                                     flag='­🥳', name='Test XA', numeric='991', official_name='Test Country XA' )

    _add_country(pycountry.countries, alpha_2='XB', alpha_3='XXB', common_name='Test XB',
                                     flag='­🙃', name='Test XB', numeric='992', official_name='Test Country Iks Beh' )

    def glob_files(country_code='*', base_dir='.'):
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

        return found_files
        
    pem_files = glob_files( metafunc.config.getoption("country_code") )
    
    if "cert" in metafunc.fixturenames:
        metafunc.parametrize("cert", pem_files, indirect=True)

_cert_cache = {}
@pytest.fixture
def cert(request):
    "the pem file that should be tested"
    if not request.param in _cert_cache:
        _cert_cache[request.param] = PemFileWrapper(request.param)
    return _cert_cache[request.param]

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
            for ex in self.x509.extensions:
                self.extensions[ ex.oid.dotted_string ] = ex 
                if not ex.oid._name == 'Unknown OID':
                    self.extensions[ ex.oid._name ] = ex
        except ValueError:
            pass # Could not load extensions


        try: 
            path = self.file_name.split(os.sep)
            self.pathinfo['type'] = path[-2] # up, csca, auth
            self.pathinfo['domain'] = path[-3] # DCC, DIVOC, SHC
            self.pathinfo['country'] = path[-5] # GER, BEL, FIN ...
        except:
            pass

