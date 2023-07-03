import pytest
import functools
import pycountry
from cryptography import x509
from cryptography.x509 import ObjectIdentifier as OID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa
'''
Tests defined by this document:
    https://github.com/WorldHealthOrganization/tng-participants-dev/blob/main/README.md#qa-checks  

'''

def test_valid_pem(cert):
    '''The certificates will be checked for a valid pem structure.
       Loading of the pem file happens during parametrization of the test cases. 
       This test checks whether there has been an error during that phase. 
    '''
    if not cert.error is None: 
        raise cert.error


def requires_readable_cert(func):
    'Decorator for tests that should be skipped if the cert has not been loaded'
    @functools.wraps(func)
    def wrapper(cert, *args, **kwargs):
        if not cert or cert.error: 
            pytest.skip(reason='Certificate could not be loaded')
        else: 
            return func(cert,*args, **kwargs)
    return wrapper

@requires_readable_cert
def test_key_length(cert):
    'The key length should be for RSA-PSS and DSS minimum 3072, and for EC-DSA 256 bit'

    public_key = cert.x509.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        assert public_key.key_size >= 3072, f'RSA Key not long enough: {public_key.key_size}'
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        assert public_key.curve.key_size >= 256, f'EC Key not long enough: {public_key.curve.key_size}'
    elif isinstance(public_key, dsa.DSAPublicKey):
        assert public_key.key_size >= 3072, f'DSA Key not long enough: {public_key.key_size}'
    else:
        assert False, 'Unsupported key type'
    
@requires_readable_cert
def test_algorithm(cert):
    'Algorithm must be in allowed list'
    assert isinstance(cert.x509, x509.Certificate)
    allowed_OIDs = (OID('1.2.840.10045.4.3.2'), # ecdsa-with-SHA256
                    #OID('1.2.840.10045.4.3.3'), # ecdsa-with-SHA384
                    OID('1.2.840.113549.1.1.10'), # rsassa-pss
                    OID('2.16.840.1.101.3.4.3.2'), # dsaWithSha256
                    OID('1.2.840.113549.1.1.11'), # Legacy: sha256WithRSAEncryption
                    )
    
    assert cert.x509.signature_algorithm_oid in allowed_OIDs, f'Signature algorithm not allowed: {cert.x509.signature_algorithm_oid}'    

@requires_readable_cert
def test_subject_format(cert, pytestconfig):
    country_attributes = cert.x509.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
    assert len(country_attributes) == 1, 'Certificate must have 1 C attribute'
    #common_name_attributes = cert.x509.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    #assert len(common_name_attributes) == 1, 'Certificate must have 1 CN attribute'


@requires_readable_cert
def test_country_flag(cert, pytestconfig):
    'The country flag (C value) must be set to the correct country code'

    if not pytestconfig.getoption('country_mode'): 
        pytest.skip(reason='This test only runs in country mode')

    country_attributes = cert.x509.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
    
    if not country_attributes:
        # Check 1: Country attribute must be present
        assert False, 'No country attribute found'
    else:
        # Check 2: Country must be in the list of existing countries
        country = pycountry.countries.lookup(country_attributes[0].value)

    # Check 3: Country in path must match country of C attribute
    assert cert.pathinfo.get('country') == country.alpha_3

@requires_readable_cert
def test_oversea_territory_ou(cert):
    pytest.skip(reason='Not implemented yet') # TODO: implement for ICAO

    state_prov_attr = cert.x509.subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)
    ju_country_attr = cert.x509.subject.get_attributes_for_oid(x509.NameOID.JURISDICTION_COUNTRY_NAME)

@requires_readable_cert
def test_explicit_parameter(cert):
    pytest.skip(reason='Not implemented yet') # TODO: implement for ICAO
    
@requires_readable_cert
def test_validity_range(cert):    
    '''SCA must be valid for at least 2 years and at most 4 years,
       UP, TLS must be valid for at least 1 year and at most 2 years
    '''
    validity = cert.x509.not_valid_after - cert.x509.not_valid_before
    
    if cert.pathinfo.get('group').upper() == 'SCA':
        min_years, max_years = 2, 4
    else: 
        min_years, max_years = 1, 2

    assert  validity > timedelta(days=min_years*365), \
       f"{cert.pathinfo.get('group')} must be valid for at least {min_years} years (is: {validity.days} days)"
    assert validity < timedelta(days=max_years*366), \
       f"{cert.pathinfo.get('group')} must be valid for at most {max_years} years (is: {validity.days} days)"

@requires_readable_cert
def test_validity(cert):    
    '''Onboarded certificates must be valid for at least 30 days from now'''
    assert cert.x509.not_valid_after >= datetime.now()+timedelta(days=30),\
        "Certificate expires in less than 30 days"

@requires_readable_cert
def test_extended_key_usages(cert):
    """Extended key usage for TLS and UP certs must be set"""
    if cert.pathinfo.get('group').upper() == 'SCA'\
    or cert.pathinfo.get('group').upper() == 'TLS' and cert.pathinfo.get('filename').upper().startswith('CA'):
        pytest.skip(reason='CA/SCA certs do not require extended key usage')

    assert '2.5.29.37' in cert.extensions, 'extendedKeyUsage not in extensions'
    usages = cert.extensions['2.5.29.37'].value._usages
    
    if cert.pathinfo.get('group').upper() == 'TLS'\
    and cert.pathinfo.get('filename').upper().startswith('CA'):
        assert x509.ObjectIdentifier('1.3.6.1.5.5.7.3.2') in usages, 'AUTH certificates must allow clientAuthentication'

@requires_readable_cert
def test_key_usages(cert):
    """Check if the certificates have the required keyUsage flags 
       depending on certificate group and file name"""
    assert '2.5.29.15' in cert.extensions, 'keyUsage not in x509 extensions'
    usages = cert.extensions['2.5.29.15'].value

    # TLS client certs in TLS group
    if cert.pathinfo.get('group').upper() == 'TLS'\
    and cert.pathinfo.get('filename').startswith('TLS'):  
        assert usages.digital_signature == True, 'TLS cert should have usage flag "digital signature"'
        assert usages.crl_sign == False, 'TLS cert should not have usage flag "CRL sign"'
        # ... TODO
    # CA certs in TLS group
    elif cert.pathinfo.get('group').upper() == 'TLS'\
    and cert.pathinfo.get('filename').upper().startswith('CA'):  
        pass
    elif cert.pathinfo.get('group').upper() == 'UP':  
        assert usages.digital_signature == True, 'UP cert should have usage flag "digital signature"'
        assert usages.crl_sign == False, 'UP cert should not have usage flag "CRL sign"'
        # ... TODO
    elif cert.pathinfo.get('group').upper() == 'SCA':
        assert usages.key_cert_sign == True, 'SCA should have usage flag "key cert sign"'

@requires_readable_cert
def test_basic_constraints(cert):
    '''Only CA and SCA certs may have a CA:TRUE constraint'''

    assert '2.5.29.19' in cert.extensions, 'basicConstraints not in x509 extensions'
    basicConstraints = cert.extensions['2.5.29.19'].value

    if cert.pathinfo.get('group').upper() == 'SCA'\
    or cert.pathinfo.get('group').upper() == 'TLS' and cert.pathinfo.get('filename').upper().startswith('CA'):
        assert basicConstraints.ca == True, 'SCA and CA certs must have basicConstraints(CA:TRUE)'
        assert not basicConstraints.path_length, 'Path length must be 0 or None'
    else:
        assert not basicConstraints.ca == True, 'non-CA certs must NOT have basicConstraints(CA:TRUE)'

def test_valid_group(cert):
    'The group in the path name must be valid'
    group = cert.pathinfo.get('group')
    assert group, 'Certificate at incorrect location'
    assert group.upper() in ('UP', 'SCA', 'TLS'), 'Invalid group: ' + group

def test_valid_domain(cert):
    'The domain in the path name must be valid'

    domain = cert.pathinfo.get('domain')
    assert domain, 'Certificate at incorrect location'
    assert domain.upper() in ('DCC','DDCC','DIVOC','ICAO','SHC'), 'Invalid domain: ' + domain
    