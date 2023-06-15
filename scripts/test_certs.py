import pytest
import pycountry
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
'''
Tests defined by this document:
    https://github.com/WorldHealthOrganization/tng-participants-dev/blob/main/README.md#qa-checks  

'''

def test_valid_pem(cert):
    'The certificates will be checked for a valid pem structure'
    if not cert.error is None: 
        raise cert.error

def test_key_length(cert):
    'The key length should be for RSA-PSS minimum 3072, and for EC-DSA 256 bit'
    if cert.error: 
        pytest.skip(reason='Certificate could not be loaded')

    public_key = cert.x509.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        assert public_key.key_size >= 3072, f'RSA Key not long enough: {public_key.key_size}'
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        assert public_key.curve.key_size >= 256, f'EC Key not long enough: {public_key.curve.key_size}'
    else:
        assert False, 'Unsupported key type'
    
def test_algorithm(cert):
    'OID TBD'
    if cert.error: 
        pytest.skip(reason='Certificate could not be loaded')
    pytest.skip(reason='OID TBD') # TODO: Implement 

def test_country_flag(cert):
    'The country flag (C value) must be set to the correct country code'
    if cert.error: 
        pytest.skip(reason='Certificate could not be loaded')

    country_attributes = cert.x509.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
    
    if not country_attributes:
        # Check 1: Country attribute must be present
        assert False, 'No country attribute found'
    else:
        # Check 2: Country must be in the list of existing countries
        country = pycountry.countries.lookup(country_attributes[0].value)

    # Check 3: Country in path must match country of C attribute
    assert cert.pathinfo.get('country') == country.alpha_3

def test_oversea_territory_ou(cert):
    'TBD' # TODO: implement
    if cert.error: 
        pytest.skip(reason='Certificate could not be loaded')

    state_prov_attr = cert.x509.subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)
    ju_country_attr = cert.x509.subject.get_attributes_for_oid(x509.NameOID.JURISDICTION_COUNTRY_NAME)
    # ...

def test_explicit_parameter(cert):
    if cert.pathinfo.get('domain').upper() == 'ICAO':
        pytest.fail('Explicit parameters for ICAO need to be defined')
    
def test_csca_validity_range(cert):
    'CSCA must be valid for at least 2 years and at most 4 years'
    pass

def test_extended_key_usages(cert):
    if cert.error: 
        pytest.skip(reason='Certificate could not be loaded')

    if cert.pathinfo.get('type').upper() == 'CSCA': 
        pytest.skip(reason='CSCA certs do not require extended key usage')

    assert '2.5.29.37' in cert.extensions, 'extendedKeyUsage not in extensions'
    usages = cert.extensions['2.5.29.37'].value._usages
    
    if cert.pathinfo.get('type').upper() == 'AUTH':  
        assert x509.ObjectIdentifier('1.3.6.1.5.5.7.3.2') in usages, 'AUTH certificates must allow clientAuthentication'

def test_key_usages(cert):
    if cert.error: 
        pytest.skip(reason='Certificate could not be loaded')


    assert '2.5.29.15' in cert.extensions, 'keyUsage not in extensions'
    usages = cert.extensions['2.5.29.15'].value

    if cert.pathinfo.get('type').upper() == 'AUTH':  
        assert usages.digital_signature == True, 'AUTH cert should have usage flag "digital signature"'
        assert usages.crl_sign == False, 'AUTH cert should not have usage flag "CRL sign"'
        # ... TODO
    elif cert.pathinfo.get('type').upper() == 'UP':  
        assert usages.digital_signature == True, 'UP cert should have usage flag "digital signature"'
        assert usages.crl_sign == False, 'UP cert should not have usage flag "CRL sign"'
        # ... TODO
    elif cert.pathinfo.get('type').upper() == 'CSCA':  
        assert usages.key_cert_sign == True, 'CSCA should have usage flag "key cert sign"'


    