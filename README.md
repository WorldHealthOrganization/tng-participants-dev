# Introduction

This repository contains the current onboarded key material in DEV environment for the Smart Trust Network. To be part of it, follow the instructions below.

# Procedure

To be part of the Smart Trust Network, copy/fork at first the [template repository](https://github.com/WorldHealthOrganization/tng-participant-template) and send an onboarding/participation request to tng-support@who.int. After verification of your request your repository will be linked with this one and your onboarding informations are replicated to the environment.

# QA Checks

Due quality reasons the incoming content will be checked for certain quality critieras. This ensures that all certificates are following the rules defined in the Smart Trust governance documents.

The incoming content needs to be checked for the following rules:

## Common Checks
|Checks|Description|Further info| Reference|
|----|-----------|-----| ---|
|Valid Folder Structure|<ul><li>[Mandatory files](scripts/tests/folder_mandatory_files.py)</li><li>[Group/Domain folder name](scripts/tests/groups_domains.py)| - | [Folder structure](#folder-structure)|
| Certificates Unique| | Certificates must be present only in one of the onboarding repositories|


## Country specific checks

|Checks|Description|Further info| Reference|
|----|-----------|-----|--- |
|[Country attribute](scripts/tests/country_flag.py)| The country flag (C value) must be set to the correct country code | Must match folder name after bot pull
|[Oversea Territory OU](scripts/tests/oversea_territory.py) | Some overseas territories require special values in their OU attribute|

## Certificate Checks

|Checks|Description|Further info| Reference|
|----|-----------|-----|---|
|[Correct PEM](scripts/tests/valid_pem.py) | The certificates will be checked for a correct pem structure|-|
|[TLS.pem without CA](scripts/tests/tls_pem_without_chain.py)| The TLS.pem must be without CA Chain|
|[Chain Check](scripts/tests/chain_check.py)| TLS.PEM + CA.PEM must resolve and verify| 
|[Validity](scripts/tests/validity.py)| Certs must be valid for at least 30 days from today |
|[Validity Range](scripts/tests/validity_range.py)| Rules according to certificate Governance | [Certificate Covernance](https://github.com/WorldHealthOrganization/smart-trust/blob/main/input/pagecontent/concepts_certificate_governance.md)
|[Key Usages](scripts/tests/key_usage.py)| Rules according to certificate Governance | [Certificate Covernance](https://github.com/WorldHealthOrganization/smart-trust/blob/main/input/pagecontent/concepts_certificate_governance.md)
|[Extended Key Usages](scripts/tests/extended_key_usage.py)| Rules according to certificate Governance | [Certificate Covernance](https://github.com/WorldHealthOrganization/smart-trust/blob/main/input/pagecontent/concepts_certificate_governance.md)
|[Basic constraints](scripts/tests/basic_constraints.py)| Rules according to certificate Governance | [Certificate Covernance](https://github.com/WorldHealthOrganization/smart-trust/blob/main/input/pagecontent/concepts_certificate_governance.md)
|[Subject](scripts/tests/subject_format.py)| Country attribute must be set in subject |

## Cryptographic Checks
|Checks|Description|Further info|Reference|
|----|-----------|-----|---|
|[Key Length](scripts/tests/key_length.py)| The key length should be for RSA-PSS minimum 3072, and for EC-DSA 256 bit|
|[Algorithm](scripts/tests/signature_algorithm.py)| RSASSA-PSS, ECDSA_P256 or DSA (legacy RSA)|
|Explicit Parameter| Only allowed in ICAO |
|Debian Weak Keys| Key must not match Debian Weak Keys | Shall ensure that nobody uses the old Open SSL Lib from Debian |

## DID Checks

|Checks|Description|Further info|Reference|
|----|-----------|-----|---|
| DID Resolvable| DID must be resolvable over the Universal Verifier||
| DID Web Domain Linkage| The DID Web domain must contain an DID Configuration||
| JWK Key| Keys must be in JWK format. Public Key Base is not allowed|| 
| Verification Method Present|At least one Verification Method must be present||
| Key Unique Check| Verification Methods shall not contain the same Public Key||
| No Private JWK | JWK shall not contain private Information||

## JWKS Checks

## Transitive Trust Failure Checks

|Checks|Description|Further info|Reference|
|----|-----------|-----|---|
|JWKS Resolvable| JWKS is resolvable||
| JWKS URI Secure | JWKS URI must have and validated Domain||
| Valid JWKS Format| JWKS format must be valid||
| Key Unique Check| Verification Methods shall not contain the same Public Key||
| No Private JWK | JWK shall not contain private Information||

# QA-Rules Explained
## Common Checks
### Folder structure

- Under the onboarding folder, there must be exactly one folder for each domain that is to be onboarded 
  - See above for list of valid domains
- Every domain MUST have 
  - One `TLS` folder with at least one TLS.pem (optionally TLS_1.pem, TLS_2.pem, ...) and at least one CA.pem (optionally CA_1.pem, ...)
  - One `UP` folder with at least one UP.pem (optionally UP_1.pem, UP_2.pem, ...)
- Every domain MAY have
  - One SCA folder with at least one SCA.pem (optionally SCA_1.pem, ...)
  - One ISSUER folder with one ore more `DID.txt` and/or `JWKS.txt` (DID_1.txt,..., JWKS_1.txt)

## Certificate Checks

The most of the checks following the [Certificate Covernance](https://github.com/WorldHealthOrganization/smart-trust/blob/main/input/pagecontent/concepts_certificate_governance.md) which defines the key length and key usage critieras. Additionally there will be more checks in future refering to ICAO, DIVOC, DDCC and other domains.

## Cryptographic Checks

## Transitive Trust Failure Checks

The review process checks for any failure within the transitive trust.
