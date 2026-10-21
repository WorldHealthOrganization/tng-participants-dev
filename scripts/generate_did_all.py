'''One-time generation of did.json for all participants.

Walks every ISO3 country folder in the repository and writes
<ISO3>/onboarding/<DOMAIN>/UP/did.json for each UP/UP.pem where the did.json is
still missing. Existing did.json files are never overwritten; new and
re-onboarded countries keep being handled by generate_did.py during onboarding.

The DID document itself is built by generate_did.build_did_document, so the
identifiers follow the same rules: repository from GITHUB_REPOSITORY, branch
from the --branch argument or GITHUB_HEAD_REF / GITHUB_REF_NAME.

Usage:
    python scripts/generate_did_all.py [--root ROOT] [--branch BRANCH] [--dry-run]
'''

import os
import sys
import json
import argparse

from generate_did import build_did_document

EXCLUDED_FOLDERS = {"WHO"}


def country_folders(root):
    'Return the ISO3 style country folders (three upper case letters) under root.'
    return [
        name for name in sorted(os.listdir(root))
        if len(name) == 3 and name.isalpha() and name.isupper()
        and name not in EXCLUDED_FOLDERS
        and os.path.isdir(os.path.join(root, name))
    ]


def generate_all(root=".", branch=None, dry_run=False):
    'Generate the missing did.json files; return (generated, skipped, failed) lists of paths.'
    generated, skipped, failed = [], [], []

    for country in country_folders(root):
        onboarding_root = os.path.join(root, country, "onboarding")
        if not os.path.isdir(onboarding_root):
            continue

        for domain in sorted(os.listdir(onboarding_root)):
            up_dir = os.path.join(onboarding_root, domain, "UP")
            up_pem = os.path.join(up_dir, "UP.pem")
            did_path = os.path.join(up_dir, "did.json")
            if not os.path.isfile(up_pem):
                continue

            if os.path.exists(did_path):
                print(f"Already present, skipping: {did_path}", flush=True)
                skipped.append(did_path)
                continue

            try:
                document = build_did_document(up_pem, country, domain, branch)
            except Exception as error:
                print(f"Failed: {up_pem}: {error}", flush=True)
                failed.append(up_pem)
                continue

            if dry_run:
                print(f"[dry-run] Would write: {did_path} ({document['id']})", flush=True)
            else:
                with open(did_path, "w", encoding="utf-8") as did_file:
                    json.dump(document, did_file, indent=4)
                    did_file.write("\n")
                print(f"Wrote: {did_path}", flush=True)
            generated.append(did_path)

    action = "Would generate" if dry_run else "Generated"
    print(
        f"{action} {len(generated)} did.json file(s), "
        f"skipped {len(skipped)} existing, {len(failed)} failed.",
        flush=True,
    )
    return generated, skipped, failed


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate the missing did.json files for all participants.")
    parser.add_argument("--root", default=".", help="repository root (default: current directory)")
    parser.add_argument("--branch", help="branch the DID documents are published on")
    parser.add_argument("--dry-run", action="store_true", help="only report what would be generated")
    parser.add_argument("--fail-on-error", action="store_true",
                        help="exit with 1 if any UP.pem could not be processed")
    args = parser.parse_args(argv)

    _, _, failed = generate_all(args.root, args.branch, args.dry_run)
    return 1 if failed and args.fail_on_error else 0


if __name__ == "__main__":
    sys.exit(main())
