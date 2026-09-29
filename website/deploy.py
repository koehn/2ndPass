#!/usr/bin/env python3
"""Upload only the built public site to an existing S3 bucket using AWS CLI."""
import argparse
from pathlib import Path
import re
import shlex
import subprocess

ROOT = Path(__file__).resolve().parent
PUBLIC_PROFILING = {
    'profiling/v7-cloud-2026-09-27.jsonl',
    'profiling/v7-engine-hardware-2026-09-27.jsonl',
    'profiling/v7-engine-software-2026-09-27.jsonl',
}


def validate_output(output):
    if not (output / 'index.html').is_file():
        raise ValueError('Build the site first: just site-build')
    # Only the reviewed measurements linked by the validation page are public.
    # Do not allow arbitrary JSONL logs merely because the build copied them.
    for path in output.rglob('*'):
        relative = path.relative_to(output).as_posix()
        if path.is_symlink() or (path.is_file() and
                path.suffix not in {'.html', '.css', '.js', '.png', '.txt', '.xml'} and
                relative not in PUBLIC_PROFILING):
            raise ValueError(f'Unexpected public output: {relative}')


def commands(bucket, prefix, distribution):
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket):
        raise ValueError('Use a bare S3 bucket name, without s3:// or a path.')
    prefix = prefix.strip('/')
    if prefix and (not re.fullmatch(r'[A-Za-z0-9_./-]+', prefix) or
                   any(part in ('', '.', '..') for part in prefix.split('/'))):
        raise ValueError('Prefix must contain ordinary path segments, without . or ...')
    if distribution and not re.fullmatch(r'[A-Z0-9]+', distribution):
        raise ValueError('Invalid CloudFront distribution ID.')
    target = f's3://{bucket}/' + (prefix + '/' if prefix else '')
    output = str(ROOT / 'dist')
    # No --delete: deploying never removes objects already in the bucket.
    result = [
        ['aws', 's3', 'sync', output, target, '--exclude', '*.html',
         '--cache-control', 'public,max-age=3600'],
        ['aws', 's3', 'cp', output, target, '--recursive', '--exclude', '*',
         '--include', '*.html', '--cache-control', 'no-cache'],
    ]
    if distribution:
        result.append(['aws', 'cloudfront', 'create-invalidation',
                       '--distribution-id', distribution, '--paths',
                       '/' + (prefix + '/' if prefix else '') + '*'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bucket')
    parser.add_argument('--prefix', default='')
    parser.add_argument('--distribution', default='')
    parser.add_argument('--dry-run', action='store_true', help='Print commands only; no AWS calls.')
    args = parser.parse_args()
    try:
        plan = commands(args.bucket, args.prefix, args.distribution)
        output = ROOT / 'dist'
        validate_output(output)
        subprocess.run(['python3', str(ROOT / 'check.py')], check=True)
        for command in plan:
            print(shlex.join(command), flush=True)
            if not args.dry_run:
                subprocess.run(command, check=True)
    except (ValueError, FileNotFoundError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
