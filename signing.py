#!/usr/bin/env python3
# Copyright 2026 The Helium Authors
# You can use, redistribute, and/or modify this source code under
# the terms of the GPL-3.0 license that can be found in the LICENSE file.
"""Sign Windows release binaries and coordinate packaging.

Without any AZURE_* signing settings, the packages are built unsigned.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

import package

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'build/src'
SIGNING_VARIABLES = ('AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET',
                     'AZURE_SIGNING_ENDPOINT', 'AZURE_SIGNING_ACCOUNT',
                     'AZURE_SIGNING_CERTIFICATE_NAME')


def run(*args, **kwargs):
    subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def pe_files(directory):
    return sorted(p for p in directory.rglob('*')
                  if p.is_file() and p.suffix.lower() in ('.exe', '.dll'))


def emit(name, value):
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            output.write(f'{name}={value}\n')


def find_signtool():
    sdk = Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)'))
    tools = list((sdk / 'Windows Kits/10/bin').glob('*/x64/signtool.exe'))
    if tools:
        return max(tools, key=lambda p: tuple(int(n) for n in p.parents[1].name.split('.')))
    tool = shutil.which('signtool')
    if tool:
        return tool
    raise FileNotFoundError('signtool.exe not found; install the Windows SDK or add x64 SignTool to PATH')


def verify_signatures(files, tool):
    if not files:
        raise ValueError('No binaries to verify')
    # /pa selects Authenticode policy; /tw warns on missing timestamps.
    # check=True rejects both failures (1) and warnings (2).
    for start in range(0, len(files), 32):
        run(tool, 'verify', '/pa', '/all', '/tw', *files[start:start + 32])


def sign(files, description, args, metadata):
    for start in range(0, len(files), 32):
        run(args.signtool, 'sign', '/fd', 'SHA256',
            '/tr', 'http://timestamp.acs.microsoft.com', '/td', 'SHA256',
            '/dlib', args.dlib, '/dmdf', metadata, '/d', description,
            '/du', 'https://github.com/anyosag/argon-windows',
            *files[start:start + 32])
    verify_signatures(files, args.signtool)


def sign_staged_binaries(work, args, metadata):
    """Sign identical binaries once and copy the result to every package layout."""
    groups = {}
    files = pe_files(work / 'portable') + pe_files(work / 'payload') + [work / 'setup.exe']
    for file in files:
        description = ('Argon Update Helper'
                       if file.name.lower() == 'helium_update_helper.exe' else 'Argon')
        groups.setdefault((description, package.digest(file)), []).append(file)
    if {description for description, _ in groups} != {'Argon', 'Argon Update Helper'}:
        raise ValueError('Expected browser and updater helper signing inputs')

    for description in ('Argon', 'Argon Update Helper'):
        originals = [paths[0] for (label, _), paths in groups.items() if label == description]
        sign(originals, description, args, metadata)
    for original, *copies in groups.values():
        for destination in copies:
            shutil.copy2(original, destination)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-outputs', type=Path, default=SOURCE / 'out/Default')
    parser.add_argument('--dlib', type=Path,
                        help="Path to the x64 Azure.CodeSigning.Dlib.dll")
    parser.add_argument('--signtool', type=Path, help='Path to x64 signtool.exe')
    parser.add_argument('--arch', choices=('x64', 'arm64'))
    parser.add_argument('--seven-zip', type=Path,
                        default=Path(shutil.which('7z') or 'C:/Program Files/7-Zip/7z.exe'))
    args = parser.parse_args()
    args.build_outputs = args.build_outputs.resolve()
    args.seven_zip = args.seven_zip.resolve()
    missing = [name for name in SIGNING_VARIABLES if not os.environ.get(name)]
    args.unsigned = len(missing) == len(SIGNING_VARIABLES)
    if args.unsigned:
        print('warn: no AZURE_* signing settings; packaging unsigned binaries')
        return args
    if missing:
        parser.error('Missing environment variables: ' + ', '.join(missing))
    if not args.dlib or not args.dlib.is_file():
        parser.error(f'Signing plugin not found: {args.dlib}')
    args.dlib = args.dlib.resolve()
    args.signtool = args.signtool.resolve() if args.signtool else find_signtool()

    return args


def write_signing_metadata(work):
    metadata = work / 'metadata.json'
    metadata.write_text(json.dumps({
        'Endpoint': os.environ['AZURE_SIGNING_ENDPOINT'],
        'CodeSigningAccountName': os.environ['AZURE_SIGNING_ACCOUNT'],
        'CertificateProfileName': os.environ['AZURE_SIGNING_CERTIFICATE_NAME'],
        # Use only EnvironmentCredential, never a runner's cached login.
        'ExcludeCredentials': [
            'ManagedIdentityCredential', 'WorkloadIdentityCredential',
            'SharedTokenCacheCredential', 'VisualStudioCredential',
            'VisualStudioCodeCredential', 'AzureCliCredential',
            'AzurePowerShellCredential', 'AzureDeveloperCliCredential',
            'InteractiveBrowserCredential',
        ],
    }), encoding='utf-8')
    return metadata


def main():
    args = parse_args()
    work = package.stage_build(args.build_outputs, args.seven_zip, args.arch)
    metadata = None if args.unsigned else write_signing_metadata(work)
    if metadata:
        sign_staged_binaries(work, args, metadata)

    # Snapshot the signed inputs before packaging so verification can detect changes.
    expected = {'payload': package.inventory(work / 'payload'),
                'portable': package.inventory(work / 'portable'),
                'setup': package.digest(work / 'setup.exe')}
    nsis, mini, portable = package.build_packages(work, args.build_outputs, args.seven_zip)
    package.verify_packages(work, args.seven_zip, nsis, mini, portable, expected)
    if metadata:
        sign([nsis, mini], 'Argon Installer', args, metadata)
    emit('artifacts', work / 'artifacts')


if __name__ == '__main__':
    main()
