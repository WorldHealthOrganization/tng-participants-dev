from common import requires_readable_cert
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa


@requires_readable_cert
def test_key_length(cert):
    'The key length should be for RSA-PSS and DSS minimum 3000, and for EC-DSA 250 bit based on https://github.com/WorldHealthOrganization/smart-trust/blob/main/input/pagecontent/concepts_certificate_governance.md'

    public_key = cert.x509.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        assert public_key.key_size >= 3000, f'RSA Key not long enough: {public_key.key_size}'
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        assert public_key.curve.key_size >= 250, f'EC Key not long enough: {public_key.curve.key_size}'
    elif isinstance(public_key, dsa.DSAPublicKey):
        assert public_key.key_size >= 3000, f'DSA Key not long enough: {public_key.key_size}'
    else:
        assert False, 'Unsupported key type'
