"""Acquire a reviewed official schema and generate an immutable local runtime bundle.

No archive members are extracted. Failed downloads and incomplete generations are
retained in .downloads. Existing generations are verified, never overwritten.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import stat
import sys
import tomllib
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MAX_DOWNLOAD = 20 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
RULE_FILES = {'ledger.json', 'ruleset.json', 'references.json',
              'rds-event-categories.json', 'service-tiers.json'}
REQUIRED_RULES = {'ledger.json', 'ruleset.json', 'references.json'}
SHA = re.compile(r'[0-9a-f]{64}')


class SchemaSetupError(ValueError):
    pass


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(data):
    return (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def no_links(path):
    """Reject links/junctions on every existing component, including the leaf."""
    for part in (path, *path.parents):
        if part.is_symlink() or getattr(part, 'is_junction', lambda: False)():
            raise SchemaSetupError('Schema paths must not contain symlinks or junctions.')


def fingerprint(path):
    no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise SchemaSetupError('A schema runtime file is missing or is not a regular file.')
    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino)


@lru_cache(maxsize=8)
def _lock(path, signature):
    value = json.loads(path.read_text(encoding='utf-8'))
    region = value.get('region', '')
    if not re.fullmatch(r'[a-z]{2}(?:-gov)?-[a-z]+-\d+', region):
        raise SchemaSetupError('Invalid locked AWS region.')
    url = f'https://schema.cloudformation.{region}.amazonaws.com/CloudformationSchema.zip'
    if value.get('format_version') != 1 or value.get('source') != url:
        raise SchemaSetupError('Unsupported schema lock or non-official source URL.')
    if not SHA.fullmatch(value.get('zip_sha256', '')) or not SHA.fullmatch(value.get('catalog_sha256', '')):
        raise SchemaSetupError('Missing reviewed archive/catalog hash; regenerate the release lock.')
    for key in ('input_sha256', 'generated_rule_sha256'):
        mapping = value.get(key, {})
        if not REQUIRED_RULES <= set(mapping) <= RULE_FILES or any(not SHA.fullmatch(v) for v in mapping.values()):
            raise SchemaSetupError('Invalid rule files in schema lock.')
    previous = value.get('previous_type_sha256', {})
    if not previous or any(not re.fullmatch(r'[A-Za-z0-9]+::[A-Za-z0-9]+::[A-Za-z0-9]+', t)
                           or not SHA.fullmatch(h) for t, h in previous.items()):
        raise SchemaSetupError('Invalid previous schema fingerprints.')
    if not SHA.fullmatch(value.get('reconciliation_sha256', '')):
        raise SchemaSetupError('Missing reconciliation hash.')
    datetime.fromisoformat(value['reviewed_at'])
    return value


def read_lock(root):
    path = root / 'schema-lock.json'
    return _lock(path, fingerprint(path))


def validate_archive(raw):
    if len(raw) > MAX_DOWNLOAD:
        raise SchemaSetupError('Schema download exceeds the size limit.')
    schemas, types, names = {}, {}, set()
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if not 1 <= len(members) <= 5000 or sum(i.file_size for i in members) > MAX_EXPANDED:
                raise SchemaSetupError('Schema archive exceeds expansion limits.')
            for item in members:
                name = item.filename
                if (not re.fullmatch(r'[a-z0-9-]+\.json', name) or name.casefold() in names
                    or item.flag_bits & 1 or stat.S_ISLNK(item.external_attr >> 16)
                    or item.file_size > 8 * 1024 * 1024):
                    raise SchemaSetupError('Unsafe or duplicate schema archive member.')
                names.add(name.casefold())
                value = json.loads(archive.read(item))  # Validates the member CRC; never extracts.
                kind = value.get('typeName')
                if (not isinstance(kind, str) or not re.fullmatch(r'[A-Za-z0-9]+::[A-Za-z0-9]+::[A-Za-z0-9]+', kind)
                    or kind in schemas or not isinstance(value.get('properties'), dict)):
                    raise SchemaSetupError('Invalid or duplicate resource schema.')
                types[kind] = name
                schemas[kind] = value
    except (zipfile.BadZipFile, UnicodeError, json.JSONDecodeError, AttributeError, RuntimeError) as exc:
        raise SchemaSetupError('Invalid or corrupt schema ZIP; retained for inspection.') from exc
    return dict(sorted(types.items())), schemas


def catalog_digest(report):
    value = {**report, 'provenance': {k: v for k, v in report['provenance'].items() if k != 'retrieved_at'}}
    return digest(encode(value))


def verify_inputs(root, lock):
    version = tomllib.loads((root.parent / 'pyproject.toml').read_text(encoding='utf-8'))['project']['version']
    if version != lock['tool_version']:
        raise SchemaSetupError('Tool version differs from the reviewed schema lock.')
    for name, expected in lock['input_sha256'].items():
        path = root.parent / 'rules' / name
        fingerprint(path)
        if digest(path.read_bytes()) != expected:
            raise SchemaSetupError('Rule inputs changed; regenerate and review the schema lock.')


def generate_bundle(raw, stage, root, lock):
    """Build only inside an exclusive staging directory; used by the release preparer too."""
    from .schema_diff import reconcile_from_hashes
    from .document_catalog import Catalog
    from .ledger import validate_ledger
    types, schemas = validate_archive(raw)
    schema_dir, rule_dir = stage / 'schemas', stage / 'rules'
    schema_dir.mkdir()
    rule_dir.mkdir()
    (schema_dir / 'CloudformationSchema.zip').write_bytes(raw)
    manifest = {'source': lock['source'], 'region': lock['region'], 'zip_sha256': digest(raw),
                'archive': 'CloudformationSchema.zip', 'types': types,
                'retrieved_at': datetime.now(timezone.utc).isoformat(), 'tool_version': lock['tool_version']}
    (schema_dir / 'manifest.json').write_bytes(encode(manifest))
    for name in lock['input_sha256']:
        shutil.copyfile(root.parent / 'rules' / name, rule_dir / name)
    changes = reconcile_from_hashes(rule_dir, lock['previous_type_sha256'], schemas, manifest, lock['reviewed_at'][:10])
    (stage / 'reconciliation.json').write_bytes(encode(changes))
    validate_ledger(rule_dir / 'ledger.json', schema_dir, rule_dir / 'ruleset.json')
    report = Catalog(schema_dir, expected_pin=lock['zip_sha256']).report()
    (stage / 'catalog.json').write_bytes(encode(report))
    return {'catalog_sha256': catalog_digest(report),
            'generated_rule_sha256': {name: digest((rule_dir / name).read_bytes()) for name in lock['input_sha256']},
            'reconciliation_sha256': digest((stage / 'reconciliation.json').read_bytes())}


def verify_bundle(root, bundle, lock):
    verify_inputs(root, lock)
    for name in ('generation.json', 'catalog.json', 'reconciliation.json', 'schemas/manifest.json', 'schemas/CloudformationSchema.zip'):
        fingerprint(bundle / name)
    receipt = json.loads((bundle / 'generation.json').read_text(encoding='utf-8'))
    if (receipt.get('lock_sha256') != digest((root / 'schema-lock.json').read_bytes())
        or receipt.get('tool_version') != lock['tool_version']):
        raise SchemaSetupError('Cache was generated with a different lock; preserve it and use a fresh release copy.')
    raw = (bundle / 'schemas/CloudformationSchema.zip').read_bytes()
    if digest(raw) != lock['zip_sha256']:
        raise SchemaSetupError('Cached schema hash mismatch; no files were replaced.')
    types, _ = validate_archive(raw)
    manifest = json.loads((bundle / 'schemas/manifest.json').read_text(encoding='utf-8'))
    expected = {'source': lock['source'], 'region': lock['region'], 'zip_sha256': lock['zip_sha256'],
                'archive': 'CloudformationSchema.zip', 'types': types, 'tool_version': lock['tool_version']}
    if any(manifest.get(k) != v for k, v in expected.items()):
        raise SchemaSetupError('Cached schema manifest differs from the reviewed archive.')
    datetime.fromisoformat(manifest['retrieved_at'])
    for name, expected_hash in lock['generated_rule_sha256'].items():
        path = bundle / 'rules' / name
        fingerprint(path)
        if digest(path.read_bytes()) != expected_hash:
            raise SchemaSetupError('Generated rules/catalog mismatch; preserve the cache and regenerate.')
    report = json.loads((bundle / 'catalog.json').read_text(encoding='utf-8'))
    if catalog_digest(report) != lock['catalog_sha256'] or report['provenance']['retrieved_at'] != manifest['retrieved_at']:
        raise SchemaSetupError('Generated documentation catalog mismatch; regenerate the release lock.')
    if digest((bundle / 'reconciliation.json').read_bytes()) != lock['reconciliation_sha256']:
        raise SchemaSetupError('Schema reconciliation record mismatch.')
    return bundle / 'schemas'


@lru_cache(maxsize=4)
def _verified(root, signatures):
    lock = read_lock(root)
    return verify_bundle(root, root / '.cache' / lock['zip_sha256'], lock)


def resolve_schema_dir(root):
    """Keep legacy developer snapshots supported; released packages require a valid cache."""
    root = Path(root).absolute()
    if not (root / 'schema-lock.json').exists():
        return root
    try:
        lock = read_lock(root)
        bundle = root / '.cache' / lock['zip_sha256']
        paths = [root / 'schema-lock.json', root.parent / 'pyproject.toml']
        paths += [root.parent / 'rules' / n for n in lock['input_sha256']]
        paths += [bundle / 'rules' / n for n in lock['generated_rule_sha256']]
        paths += [bundle / n for n in ('generation.json', 'catalog.json', 'reconciliation.json', 'schemas/manifest.json', 'schemas/CloudformationSchema.zip')]
        return _verified(root, tuple(fingerprint(p) for p in paths))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        if isinstance(exc, SchemaSetupError):
            raise
        raise SchemaSetupError('Schema setup is missing or invalid. Run aws-design-bootstrap; existing files will be preserved.') from exc


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SchemaSetupError('Official schema download redirected; review the source before proceeding.')


def download(url, destination):
    opener = urllib.request.build_opener(NoRedirect)
    total = 0
    with opener.open(url, timeout=120) as response, destination.open('xb') as stream:
        while chunk := response.read(64 * 1024):
            total += len(chunk)
            if total > MAX_DOWNLOAD:
                raise SchemaSetupError('Official schema download exceeds the size limit.')
            stream.write(chunk)
    return destination.read_bytes()


def setup(root, *, check_only=False):
    root = Path(root).absolute()
    no_links(root)
    lock = read_lock(root)
    verify_inputs(root, lock)
    cache = root / '.cache'
    bundle = cache / lock['zip_sha256']
    no_links(bundle)
    if bundle.exists():
        verify_bundle(root, bundle, lock)
        return {'status': 'CACHED', 'offline': True, 'schema_dir': str(bundle / 'schemas'), 'zip_sha256': lock['zip_sha256']}
    if check_only:
        raise SchemaSetupError('Reviewed schema cache is absent; initial setup needs an internet connection.')
    attempts = root / '.downloads'
    no_links(attempts)
    attempts.mkdir(exist_ok=True)
    stage = attempts / uuid.uuid4().hex
    stage.mkdir()
    try:
        raw = download(lock['source'], stage / 'download.partial')
        if digest(raw) != lock['zip_sha256']:
            raise SchemaSetupError('Official URL content changed. Obtain a reviewed release/schema lock; do not unpin the hash.')
        actual = generate_bundle(raw, stage, root, lock)
        if any(actual[k] != lock[k] for k in actual):
            raise SchemaSetupError('Generated catalog differs from the reviewed lock; release regeneration is required.')
        receipt = {'lock_sha256': digest((root / 'schema-lock.json').read_bytes()), 'tool_version': lock['tool_version'],
                   'python_version': sys.version.split()[0], 'completed_at': datetime.now(timezone.utc).isoformat()}
        (stage / 'generation.json').write_bytes(encode(receipt))
        verify_bundle(root, stage, lock)
        cache.mkdir(exist_ok=True)
        # Exclusive reservation works on Windows and POSIX. The completion marker
        # moves last; readers reject any incomplete activation. Never overwrite.
        bundle.mkdir()
        for child in stage.iterdir():
            if child.name != 'generation.json':
                child.rename(bundle / child.name)
        (stage / 'generation.json').rename(bundle / 'generation.json')
        return {'status': 'CREATED', 'offline': False, 'schema_dir': str(bundle / 'schemas'), 'zip_sha256': lock['zip_sha256']}
    except Exception as exc:
        if stage.exists():
            (stage / 'failure.json').write_bytes(encode({'status': 'FAILED', 'error_type': type(exc).__name__,
                'message': 'Incomplete generation preserved. Active cache was not replaced.'}))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schemas', type=Path, default=ROOT / 'schemas')
    parser.add_argument('--check', action='store_true', help='verify an existing cache without network access')
    args = parser.parse_args(argv)
    try:
        result = setup(args.schemas, check_only=args.check)
    except Exception as exc:
        message = str(exc) if isinstance(exc, SchemaSetupError) else 'Schema setup failed; inspect the preserved attempt and retry. No credentials are required.'
        print(json.dumps({'status': 'FAILED', 'error_type': type(exc).__name__, 'message': message}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
