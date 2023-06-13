import pytest
import pycountry
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

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
    pytest.skip(reason='OID TBD')

def test_country_flag(cert):
    'The country flag (C value) must be set to the correct country code'
    country_attributes = cert.x509.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
    
    if not country_attributes:
        # Check 1: Country attribute must be present
        assert False, 'No country attribute found'
    else:
        # Check 2: Country must be in the list of existing countries
        country = pycountry.countries.lookup(country_attributes[0].value)

    # Check 3: Country in path must match country of C attribute
    assert cert.pathinfo.get('country') == country.alpha_3
