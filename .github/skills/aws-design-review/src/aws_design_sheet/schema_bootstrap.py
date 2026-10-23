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
              'rds-event-categories.json', 'service-tiers.json', 'schema-reviews.json'}
REQUIRED_RULES = {'ledger.json', 'ruleset.json', 'references.json'}
SHA = re.compile(r'[0-9a-f]{64}')
# Format-3 locks: the official URL serves only the latest archive, which AWS
# rebuilds several times a day. A newer archive is accepted, its per-type drift
# from the reviewed archive is recorded, and the rule ledger is reconciled so
# changed types are never treated as reviewed.
DRIFT_POLICY = 'OFFICIAL_LATEST_WITH_REVIEW_DRIFT'


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
    if value.get('format_version') not in (1, 2, 3) or value.get('source') != url:
        raise SchemaSetupError('Unsupported schema lock or non-official source URL.')
    if value['format_version'] == 3:
        reviewed = value.get('reviewed_type_sha256', {})
        if (value.get('acquisition') != DRIFT_POLICY or not reviewed
                or any(not re.fullmatch(r'[A-Za-z0-9]+::[A-Za-z0-9]+::[A-Za-z0-9]+', t) or not SHA.fullmatch(h)
                       for t, h in reviewed.items())):
            raise SchemaSetupError('Invalid reviewed type fingerprints in schema lock.')
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


def lock_path(root, region=None):
    """Select an explicit regional lock, never fall back to another region."""
    root = Path(root)
    default = root / 'schema-lock.json'
    if region is None:
        return default
    if not re.fullmatch(r'[a-z]{2}(?:-gov)?-[a-z]+-\d+', region):
        raise SchemaSetupError('Invalid requested AWS region.')
    if default.exists() and _lock(default, fingerprint(default))['region'] == region:
        return default
    return root / f'schema-lock.{region}.json'


def read_lock(root, region=None):
    path = lock_path(root, region)
    try:
        value = _lock(path, fingerprint(path))
    except OSError as exc:
        raise SchemaSetupError(f'No reviewed schema lock for region {region or "default"}.') from exc
    if region is not None and value['region'] != region:
        raise SchemaSetupError('Requested region differs from the selected schema lock.')
    return value


def bundle_path(root, lock, zip_sha256=None):
    if lock['format_version'] == 1:
        return root / '.cache' / lock['zip_sha256']
    # A new catalog/lock never overwrites an older cache for the same AWS ZIP.
    return root / '.cache' / lock['region'] / (zip_sha256 or lock['zip_sha256']) / digest(encode(lock))


def active_bundle(root, lock):
    """The reviewed-archive cache, or the single drifted cache generated for this lock."""
    exact = bundle_path(root, lock)
    if lock['format_version'] < 3 or exact.exists():
        return exact
    region = root / '.cache' / lock['region']
    no_links(region)
    found = sorted(p.parent for p in region.glob('*/' + digest(encode(lock)) + '/generation.json')) if region.is_dir() else []
    if len(found) > 1:
        raise SchemaSetupError('Several schema caches exist for this lock; keep one or use a fresh release copy.')
    return found[0] if found else exact


def review_drift(lock, raw, zip_sha256):
    """Per-type differences between the reviewed archive and the acquired one."""
    from .schema_diff import _digest
    _, schemas = validate_archive(raw)
    reviewed = lock['reviewed_type_sha256']
    actual = {t: _digest(s) for t, s in schemas.items()}
    return {'reviewed_zip_sha256': lock['zip_sha256'], 'zip_sha256': zip_sha256,
            'added': sorted(set(actual) - set(reviewed)), 'removed': sorted(set(reviewed) - set(actual)),
            'changed': sorted(t for t in set(actual) & set(reviewed) if actual[t] != reviewed[t])}


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


def review_manifest(drift):
    exact = drift['zip_sha256'] == drift['reviewed_zip_sha256']
    return {'review_status': 'REVIEWED_EXACT' if exact else 'DRIFTED_FROM_REVIEWED',
            'reviewed_zip_sha256': drift['reviewed_zip_sha256'],
            'review_drift': {k: len(drift[k]) for k in ('added', 'removed', 'changed')}}


def review_result(manifest):
    """Setup output: format-1/2 caches are exact pins by construction."""
    return {k: manifest.get(k, d) for k, d in (('review_status', 'PINNED_EXACT'), ('review_drift', {}))}


def verify_inputs(root, lock):
    version = tomllib.loads((root.parent / 'pyproject.toml').read_text(encoding='utf-8'))['project']['version']
    if version != lock['tool_version']:
        raise SchemaSetupError('Tool version differs from the reviewed schema lock.')
    for name, expected in lock['input_sha256'].items():
        path = root.parent / 'rules' / name
        fingerprint(path)
        if digest(path.read_bytes()) != expected:
            raise SchemaSetupError('Rule inputs changed; regenerate and review the schema lock.')


def generate_bundle(raw, stage, root, lock, drift=None):
    """Build only inside an exclusive staging directory; used by the release preparer too."""
    from .schema_diff import _digest, reconcile_from_hashes
    from .schema_reviews import REGIONAL_QUESTION, accepted, load
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
    if lock['format_version'] == 3:
        drift = drift or review_drift(lock, raw, digest(raw))
        manifest.update(review_manifest(drift))
        (stage / 'drift.json').write_bytes(encode(drift))
    (schema_dir / 'manifest.json').write_bytes(encode(manifest))
    for name in lock['input_sha256']:
        shutil.copyfile(root.parent / 'rules' / name, rule_dir / name)
    records = load(rule_dir)
    changes = reconcile_from_hashes(rule_dir, lock['previous_type_sha256'], schemas, manifest, lock['reviewed_at'][:10],
                                    accepted(records, 'SCHEMA_CHANGE', lock['region']))
    if lock.get('baseline_region', lock['region']) != lock['region']:
        # Matching property hashes do not establish regional applicability of prose rules;
        # only a recorded review of this region's exact type schema keeps the baseline state.
        ledger_path = rule_dir / 'ledger.json'
        ledger = json.loads(ledger_path.read_text(encoding='utf-8'))
        reviewed = accepted(records, 'REGIONAL_APPLICABILITY', lock['region'], lock['baseline_region'])
        changed, kept = [], []
        for kind, entry in ledger['types'].items():
            if entry['state'] == 'UNRESEARCHED':continue
            if kind in reviewed and kind in schemas and reviewed[kind] == _digest(schemas[kind]):
                kept.append(kind);continue
            entry['state'] = 'REVIEW_REQUIRED'
            question = REGIONAL_QUESTION.format(region=lock['region'], baseline=lock['baseline_region'])
            if question not in entry['open_questions']:entry['open_questions'].append(question)
            changed.append(kind)
        ledger_path.write_bytes(encode(ledger))
        changes['regional_review_required'] = sorted(changed)
        if kept:changes['regional_review_accepted'] = sorted(kept)
    (stage / 'reconciliation.json').write_bytes(encode(changes))
    validate_ledger(rule_dir / 'ledger.json', schema_dir, rule_dir / 'ruleset.json')
    # The manifest records this archive's own hash; setup has compared it with the lock.
    report = Catalog(schema_dir, expected_pin=manifest['zip_sha256']).report()
    (stage / 'catalog.json').write_bytes(encode(report))
    return {'catalog_sha256': catalog_digest(report), 'catalog_types': sorted(report['resources']),
            'generated_rule_sha256': {name: digest((rule_dir / name).read_bytes()) for name in lock['input_sha256']},
            'reconciliation_sha256': digest((stage / 'reconciliation.json').read_bytes())}


def verify_bundle(root, bundle, lock):
    verify_inputs(root, lock)
    for name in ('generation.json', 'catalog.json', 'reconciliation.json', 'schemas/manifest.json', 'schemas/CloudformationSchema.zip'):
        fingerprint(bundle / name)
    receipt = json.loads((bundle / 'generation.json').read_text(encoding='utf-8'))
    if (receipt.get('lock_sha256') != digest(lock_path(root, lock['region']).read_bytes())
        or receipt.get('tool_version') != lock['tool_version']):
        raise SchemaSetupError('Cache was generated with a different lock; preserve it and use a fresh release copy.')
    raw = (bundle / 'schemas/CloudformationSchema.zip').read_bytes()
    drift = None
    if lock['format_version'] == 3:
        fingerprint(bundle / 'drift.json')
        drift_raw = (bundle / 'drift.json').read_bytes()
        drift = json.loads(drift_raw)
        if receipt.get('drift_sha256') != digest(drift_raw) or drift != review_drift(lock, raw, digest(raw)):
            raise SchemaSetupError('Schema review drift record mismatch; preserve the cache and regenerate.')
        if drift['zip_sha256'] != lock['zip_sha256']:
            # A drifted archive cannot match reviewed artifacts; its own generated
            # hashes are bound to this lock by the receipt instead.
            generated = receipt.get('generated', {})
            if set(generated) != {'catalog_sha256', 'catalog_types', 'generated_rule_sha256', 'reconciliation_sha256'}:
                raise SchemaSetupError('Drifted schema cache lacks its generation record; regenerate.')
            lock = {**lock, **generated, 'zip_sha256': drift['zip_sha256']}
    if digest(raw) != lock['zip_sha256']:
        raise SchemaSetupError('Cached schema hash mismatch; no files were replaced.')
    types, _ = validate_archive(raw)
    manifest = json.loads((bundle / 'schemas/manifest.json').read_text(encoding='utf-8'))
    expected = {'source': lock['source'], 'region': lock['region'], 'zip_sha256': lock['zip_sha256'],
                'archive': 'CloudformationSchema.zip', 'types': types, 'tool_version': lock['tool_version'],
                **(review_manifest(drift) if drift else {})}
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
    if 'catalog_types' in lock and sorted(report['resources']) != lock['catalog_types']:
        raise SchemaSetupError('Regional catalog type inventory differs from its lock.')
    if digest((bundle / 'reconciliation.json').read_bytes()) != lock['reconciliation_sha256']:
        raise SchemaSetupError('Schema reconciliation record mismatch.')
    return bundle / 'schemas'


@lru_cache(maxsize=4)
def _verified(root, region, signatures):
    lock = read_lock(root, region)
    return verify_bundle(root, active_bundle(root, lock), lock)


def resolve_schema_dir(root, region=None):
    """Keep legacy developer snapshots supported; released packages require a valid cache."""
    root = Path(root).absolute()
    selected = lock_path(root, region)
    if not selected.exists() and not (root / 'schema-lock.json').exists():
        if region is None:
            return root
        manifest = root / 'manifest.json'
        if manifest.exists() and json.loads(manifest.read_text(encoding='utf-8')).get('region') == region:
            return root
        raise SchemaSetupError(f'No reviewed schema snapshot for region {region}.')
    try:
        lock = read_lock(root, region)
        bundle = active_bundle(root, lock)
        paths = [selected, root.parent / 'pyproject.toml']
        paths += [root.parent / 'rules' / n for n in lock['input_sha256']]
        paths += [bundle / 'rules' / n for n in lock['generated_rule_sha256']]
        paths += [bundle / n for n in ('generation.json', 'catalog.json', 'reconciliation.json', 'schemas/manifest.json', 'schemas/CloudformationSchema.zip')]
        if lock['format_version'] == 3:paths.append(bundle / 'drift.json')
        return _verified(root, region, tuple(fingerprint(p) for p in paths))
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


def setup(root, *, check_only=False, region=None):
    root = Path(root).absolute()
    no_links(root)
    lock = read_lock(root, region)
    verify_inputs(root, lock)
    bundle = active_bundle(root, lock)
    cache = bundle.parent
    no_links(bundle)
    if bundle.exists():
        verify_bundle(root, bundle, lock)
        manifest = json.loads((bundle / 'schemas/manifest.json').read_text(encoding='utf-8'))
        return {'status': 'CACHED', 'offline': True, 'region': lock['region'], 'schema_dir': str(bundle / 'schemas'),
                'zip_sha256': manifest['zip_sha256'], **review_result(manifest)}
    if check_only:
        raise SchemaSetupError('Reviewed schema cache is absent; initial setup needs an internet connection.')
    attempts = root / '.downloads'
    no_links(attempts)
    attempts.mkdir(exist_ok=True)
    stage = attempts / uuid.uuid4().hex
    stage.mkdir()
    try:
        raw = download(lock['source'], stage / 'download.partial')
        zip_sha256 = digest(raw); drift = None
        if zip_sha256 != lock['zip_sha256']:
            if lock['format_version'] < 3:
                raise SchemaSetupError('Official URL content changed. Obtain a reviewed release/schema lock; do not unpin the hash.')
            drift = review_drift(lock, raw, zip_sha256)
            bundle = bundle_path(root, lock, zip_sha256); cache = bundle.parent
            no_links(bundle)
        actual = generate_bundle(raw, stage, root, lock, drift)
        # Format-1 locks predate the optional type inventory. All originally
        # pinned hashes remain mandatory; absence is permitted only for inventory.
        if drift is None and any(actual[k] != lock[k] for k in actual if k != 'catalog_types' or k in lock):
            raise SchemaSetupError('Generated catalog differs from the reviewed lock; release regeneration is required.')
        receipt = {'lock_sha256': digest(lock_path(root, lock['region']).read_bytes()), 'tool_version': lock['tool_version'],
                   'python_version': sys.version.split()[0], 'completed_at': datetime.now(timezone.utc).isoformat()}
        if lock['format_version'] == 3:
            receipt.update(generated=actual, drift_sha256=digest((stage / 'drift.json').read_bytes()))
        (stage / 'generation.json').write_bytes(encode(receipt))
        verify_bundle(root, stage, lock)
        cache.mkdir(parents=True, exist_ok=True)
        # Exclusive reservation works on Windows and POSIX. The completion marker
        # moves last; readers reject any incomplete activation. Never overwrite.
        bundle.mkdir()
        for child in stage.iterdir():
            if child.name != 'generation.json':
                child.rename(bundle / child.name)
        (stage / 'generation.json').rename(bundle / 'generation.json')
        manifest = json.loads((bundle / 'schemas/manifest.json').read_text(encoding='utf-8'))
        return {'status': 'CREATED', 'offline': False, 'region': lock['region'], 'schema_dir': str(bundle / 'schemas'),
                'zip_sha256': zip_sha256, **review_result(manifest)}
    except Exception as exc:
        if stage.exists():
            (stage / 'failure.json').write_bytes(encode({'status': 'FAILED', 'error_type': type(exc).__name__,
                'message': 'Incomplete generation preserved. Active cache was not replaced.'}))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schemas', type=Path, default=ROOT / 'schemas')
    parser.add_argument('--check', action='store_true', help='verify an existing cache without network access')
    parser.add_argument('--region', help='select a reviewed regional lock; no implicit fallback')
    parser.add_argument('--all-regions', action='store_true', help='set up all packaged regional locks')
    args = parser.parse_args(argv)
    try:
        if args.region and args.all_regions:
            parser.error('--region and --all-regions are mutually exclusive')
        if args.all_regions:
            regions = {read_lock(args.schemas)['region']}
            regions.update(p.name[len('schema-lock.'):-len('.json')] for p in args.schemas.glob('schema-lock.*.json'))
            result = {'status': 'COMPLETE', 'regions': [setup(args.schemas, check_only=args.check, region=r) for r in sorted(regions)]}
        else:
            result = setup(args.schemas, check_only=args.check, region=args.region)
    except Exception as exc:
        message = str(exc) if isinstance(exc, SchemaSetupError) else 'Schema setup failed; inspect the preserved attempt and retry. No credentials are required.'
        print(json.dumps({'status': 'FAILED', 'error_type': type(exc).__name__, 'message': message}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
