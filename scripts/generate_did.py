'''Generate a did.json document for each UP certificate of a country.

For every onboarding/<DOMAIN>/UP/UP.pem found under the given country folder a
DID document is written to onboarding/<DOMAIN>/UP/DID/did.json. The
publicKeyJwk is derived directly from the UP certificate so the UP public key
can be used as a trust anchor. The document intentionally contains no proof
section (it is not signed).

The did:web identifiers are environment agnostic: the repository owner and name
are read from the GITHUB_REPOSITORY environment variable (owner/repo) that
GitHub Actions provides, falling back to the default WHO repository when run
locally.
'''

import os
import sys
import json
import base64

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

DID_HOST = "raw.githubusercontent.com"
DEFAULT_REPOSITORY = "WorldHealthOrganization/tng-participants-dev"

# Map cryptography curve names to the JWK crv names (RFC 7518 / RFC 8812).
_CRV_NAMES = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
    "secp256k1": "secp256k1",
}


def _b64url(raw):
    'base64url encode without padding, as required for JWK members.'
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _did_prefix():
    'Build the environment agnostic did:web prefix from GITHUB_REPOSITORY.'
    repository = os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPOSITORY)
    owner, _, name = repository.partition("/")
    if not name:
        owner, name = DEFAULT_REPOSITORY.split("/")
    return f"did:web:{DID_HOST}:{owner}:{name}"


def _load_certificates(pem_path):
    'Return every X.509 certificate contained in a (possibly multipart) PEM file.'
    with open(pem_path, "rb") as pem_file:
        content = pem_file.read()

    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    certificates = []
    start = content.find(begin)
    while start != -1:
        stop = content.find(end, start)
        if stop == -1:
            break
        block = content[start:stop + len(end)]
        certificates.append(x509.load_pem_x509_certificate(block))
        start = content.find(begin, stop)
    return certificates


def _public_key_jwk(cert):
    'Derive the publicKeyJwk members (kty/crv/x/y or kty/n/e) from a certificate.'
    public_key = cert.public_key()

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        numbers = public_key.public_numbers()
        size = (public_key.curve.key_size + 7) // 8
        return {
            "kty": "EC",
            "crv": _CRV_NAMES.get(public_key.curve.name, public_key.curve.name),
            "x": _b64url(numbers.x.to_bytes(size, "big")),
            "y": _b64url(numbers.y.to_bytes(size, "big")),
        }

    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        n_len = (numbers.n.bit_length() + 7) // 8
        e_len = (numbers.e.bit_length() + 7) // 8
        return {
            "kty": "RSA",
            "n": _b64url(numbers.n.to_bytes(n_len, "big")),
            "e": _b64url(numbers.e.to_bytes(e_len, "big")),
        }

    raise ValueError(f"Unsupported public key type: {type(public_key).__name__}")


def build_did_document(pem_path, country, domain):
    'Build the DID document dict for the UP certificate at pem_path.'
    certificates = _load_certificates(pem_path)
    if not certificates:
        raise ValueError(f"No certificate found in {pem_path}")

    leaf = certificates[0]
    x5c = [
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
        for cert in certificates
    ]

    did_prefix = _did_prefix()
    controller = f"{did_prefix}:{country}"
    verification_id = f"{controller}:onboarding:{domain}:UP:DID"

    public_key_jwk = {"x5c": x5c}
    public_key_jwk.update(_public_key_jwk(leaf))

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": verification_id,
        "verificationMethod": [
            {
                "id": verification_id,
                "type": "JsonWebKey2020",
                "controller": controller,
                "publicKeyJwk": public_key_jwk,
            }
        ],
    }


def generate_for_country(country_folder):
    'Generate did.json for every onboarding/<DOMAIN>/UP/UP.pem under country_folder.'
    country = os.path.basename(os.path.normpath(country_folder))
    onboarding_root = os.path.join(country_folder, "onboarding")
    if not os.path.isdir(onboarding_root):
        print(f"No onboarding folder for {country}, skipping DID generation.", flush=True)
        return

    generated = 0
    for domain in sorted(os.listdir(onboarding_root)):
        up_pem = os.path.join(onboarding_root, domain, "UP", "UP.pem")
        if not os.path.isfile(up_pem):
            continue

        try:
            document = build_did_document(up_pem, country, domain)
        except Exception as error:
            print(f"Skipping DID for {up_pem}: {error}", flush=True)
            continue

        did_dir = os.path.join(onboarding_root, domain, "UP", "DID")
        os.makedirs(did_dir, exist_ok=True)
        did_path = os.path.join(did_dir, "did.json")
        with open(did_path, "w", encoding="utf-8") as did_file:
            json.dump(document, did_file, indent=4)
            did_file.write("\n")
        print(f"Wrote DID document: {did_path}", flush=True)
        generated += 1

    print(f"Generated {generated} DID document(s) for {country}.", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scripts/generate_did.py <country-folder>", file=sys.stderr)
        sys.exit(1)
    generate_for_country(sys.argv[1])
