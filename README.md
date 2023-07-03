# Introduction

This repository contains the current onboarded key material in DEV environment for the Smart Trust Network. To be part of it, follow the instructions below.

# Procedure

To be part of the Smart Trust Network, copy/fork at first the [template repository](https://github.com/WorldHealthOrganization/tng-participant-template) and send an onboarding/participation request to tng-support@who.int. After verification of your request your repository will be linked with this one and your onboarding informations are replicated to the environment.

# QA Checks

The incoming content needs to be checked for the following rules:

## Common Checks
|Checks|Description|Further info|
|----|-----------|-----|
|Valid Folder Structure|Checks if the folder structure is valid and all required files are there.| [Folder structure](#folder-structure) |
|Valid PEM | The certificates will be checked for a valid pem structure|-|
|TLS.PEM without CA| The TLS.PEM must be without CA Chain|
|CA.PEM present| The CA.PEM must be present |
| Chain Check| TLS.PEM + CA.PEM must resolve and verify| 
|Key Length| The key length should be for RSA-PSS minimum 3072, and for EC-DSA 256 bit|
|Algorithm| RSASSA-PSS, ECDSA_P256 or DSA (legacy RSA)|
|Explicit Parameter| Only allowed in ICAO | 
|Validity Range| Rules according to certificate Governance | [Certificate Covernance](https://github.com/WorldHealthOrganization/smart-trust/blob/main/input/pagecontent/concepts_certificate_governance.md)
|Key Usages| Rules according to certificate Governance | [Certificate Covernance](https://github.com/WorldHealthOrganization/smart-trust/blob/main/input/pagecontent/concepts_certificate_governance.md)
|Basic constraints| Rules according to certificate Governance | [Certificate Covernance](https://github.com/WorldHealthOrganization/smart-trust/blob/main/input/pagecontent/concepts_certificate_governance.md)
|Valid domain| Domain in path name must be one of DCC DDCC DIVOC ICAO SHC|
|Country attribute| Country attribute must be set in subject |

## Country specific checks

|Checks|Description|Further info|
|----|-----------|-----|
|Country attribute| The country flag (C value) must be set to the correct country code | Must match folder name after bot pull
|Oversea Territory OU | Some overseas territories require special values in their OU attribute|

# QA-Rules
## Folder structure
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

## Transitive Trust Failure Checks

The review process checks for any failure within the transitive trust.
