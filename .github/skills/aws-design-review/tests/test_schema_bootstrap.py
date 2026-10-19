import copy
import io
import json
from pathlib import Path
import shutil
import stat
import zipfile

import pytest

from aws_design_sheet import schema_bootstrap as boot
from aws_design_sheet.document_catalog import SERVICES
from aws_design_sheet.schema_diff import _digest


def zipped(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, value in entries:
            archive.writestr(name, value if isinstance(value, bytes) else json.dumps(value))
    return stream.getvalue()


@pytest.fixture
def release(tmp_path):
    root = tmp_path / 'package'
    schema_root = root / 'schemas'
    schema_root.mkdir(parents=True)
    (root / 'rules').mkdir()
    (root / 'pyproject.toml').write_text('[project]\nversion="0.2.0"\n', encoding='utf-8')
    values = {f'AWS::{names[0]}::Fixture': {'typeName': f'AWS::{names[0]}::Fixture',
              'properties': {'Name': {'type': 'string'}}, 'additionalProperties': False}
              for names in SERVICES.values()}
    raw = zipped([(f'aws-{n.lower()}-fixture.json', s) for n, s in zip(SERVICES, values.values())])
    ledger = {'ledger_version': '1.0.0', 'schema_region': 'ap-northeast-1', 'schema_zip_sha256': boot.digest(raw),
              'types': {t: {'service': t.split('::')[1], 'state': 'UNRESEARCHED', 'source_urls': [],
                            'rule_ids': [], 'open_questions': []} for t in values}}
    assets = {'ledger.json': ledger, 'ruleset.json': {'ruleset_version': '1.0.0', 'rules': []},
              'references.json': {'catalog_version': '1.0.0', 'references': []}}
    for name, value in assets.items():
        (root / 'rules' / name).write_bytes(boot.encode(value))
    lock = {'format_version': 1, 'region': 'ap-northeast-1', 'tool_version': '0.2.0',
            'source': 'https://schema.cloudformation.ap-northeast-1.amazonaws.com/CloudformationSchema.zip',
            'zip_sha256': boot.digest(raw), 'reviewed_at': '2026-10-13T00:00:00+00:00',
            'previous_type_sha256': {t: _digest(s) for t, s in values.items()},
            'input_sha256': {n: boot.digest((root / 'rules' / n).read_bytes()) for n in assets}}
    preview = tmp_path / 'preview'
    preview.mkdir()
    lock.update(boot.generate_bundle(raw, preview, schema_root, lock))
    (schema_root / 'schema-lock.json').write_bytes(boot.encode(lock))
    return schema_root, raw, lock


def deliver(monkeypatch, raw):
    def download(url, path):
        path.write_bytes(raw)
        return raw
    monkeypatch.setattr(boot, 'download', download)


def test_format_one_lock_without_type_inventory_can_initialize(release, monkeypatch):
    root, raw, lock = release
    lock.pop('catalog_types')
    (root/'schema-lock.json').write_bytes(boot.encode(lock))
    deliver(monkeypatch, raw)
    assert boot.setup(root)['status'] == 'CREATED'
    monkeypatch.setattr(boot, 'download', lambda *_: pytest.fail('offline cache contacted network'))
    assert boot.setup(root, check_only=True)['status'] == 'CACHED'


def regional_lock(root, raw, lock, tmp_path):
    east = {**lock, 'format_version': 2, 'region': 'us-east-1', 'baseline_region': 'ap-northeast-1',
            'source': 'https://schema.cloudformation.us-east-1.amazonaws.com/CloudformationSchema.zip'}
    preview = tmp_path / 'east-preview'
    preview.mkdir()
    east.update(boot.generate_bundle(raw, preview, root, east))
    (root / 'schema-lock.us-east-1.json').write_bytes(boot.encode(east))
    return east


def test_two_regions_same_zip_have_separate_verified_caches(release, monkeypatch, tmp_path):
    root, raw, lock = release
    east = regional_lock(root, raw, lock, tmp_path)
    deliver(monkeypatch, raw)
    tokyo = boot.setup(root)
    result = boot.setup(root, region='us-east-1')
    assert tokyo['schema_dir'] != result['schema_dir']
    assert json.loads((Path(result['schema_dir'])/'manifest.json').read_text())['region'] == 'us-east-1'
    monkeypatch.setattr(boot, 'download', lambda *_: pytest.fail('offline cache contacted network'))
    assert boot.setup(root, region='us-east-1', check_only=True)['status'] == 'CACHED'
    assert boot.resolve_schema_dir(root, 'us-east-1') == boot.bundle_path(root, east)/'schemas'
    assert boot.resolve_schema_dir(root, 'ap-northeast-1') == Path(tokyo['schema_dir'])


@pytest.mark.parametrize('region', ['us-west-2', '../us-east-1', 'us-east-1/../../'])
def test_missing_or_escaping_region_never_uses_default_lock(release, region):
    root, _, _ = release
    with pytest.raises(boot.SchemaSetupError):boot.resolve_schema_dir(root, region)


def test_wrong_named_regional_lock_is_rejected(release):
    root, _, lock = release
    (root/'schema-lock.us-east-1.json').write_bytes(boot.encode(lock))
    with pytest.raises(boot.SchemaSetupError, match='Requested region'):
        boot.read_lock(root, 'us-east-1')


def test_region_manifest_mixup_is_not_an_offline_success(release, monkeypatch, tmp_path):
    root, raw, lock = release
    regional_lock(root, raw, lock, tmp_path)
    deliver(monkeypatch, raw)
    result = boot.setup(root, region='us-east-1')
    path = Path(result['schema_dir'])/'manifest.json'
    manifest = json.loads(path.read_text());manifest['region'] = 'ap-northeast-1'
    path.write_bytes(boot.encode(manifest))
    with pytest.raises(boot.SchemaSetupError, match='manifest'):
        boot.resolve_schema_dir(root, 'us-east-1')


def test_new_lock_preserves_previous_generation_of_identical_zip(release, monkeypatch, tmp_path):
    root, raw, lock = release
    east = regional_lock(root, raw, lock, tmp_path)
    deliver(monkeypatch, raw)
    original = boot.setup(root, region='us-east-1')
    old = Path(original['schema_dir'])/'manifest.json';before = old.read_bytes()
    east['reviewed_at'] = '2026-10-14T00:00:00+00:00'
    (root/'schema-lock.us-east-1.json').write_bytes(boot.encode(east))
    after = boot.setup(root, region='us-east-1')
    assert original['schema_dir'] != after['schema_dir'] and old.read_bytes() == before


def test_success_reuse_and_offline_check_preserve_unknown_files(release, monkeypatch):
    root, raw, lock = release
    deliver(monkeypatch, raw)
    assert boot.setup(root)['status'] == 'CREATED'
    bundle = root / '.cache' / lock['zip_sha256']
    canary = bundle / 'user-note.txt'
    canary.write_text('keep me', encoding='utf-8')
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    monkeypatch.setattr(boot, 'download', lambda *_: pytest.fail('cached setup must not use network'))
    assert boot.setup(root)['status'] == 'CACHED'
    assert boot.setup(root, check_only=True)['offline']
    assert boot.resolve_schema_dir(root) == bundle / 'schemas'
    assert before == {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('payload', [b'not a zip', b'', b'partial archive'])
def test_changed_upstream_retains_attempt_without_activation(release, monkeypatch, payload):
    root, raw, lock = release
    deliver(monkeypatch, payload)
    with pytest.raises(boot.SchemaSetupError, match='content changed'):
        boot.setup(root)
    assert not (root / '.cache' / lock['zip_sha256']).exists()
    attempt = next((root / '.downloads').iterdir())
    assert (attempt / 'download.partial').read_bytes() == payload
    assert (attempt / 'failure.json').is_file()


def test_network_failure_preserves_partial_and_allows_fresh_retry(release, monkeypatch):
    root, raw, _ = release
    def fail(url, path):
        path.write_bytes(b'partial')
        raise OSError('simulated offline')
    monkeypatch.setattr(boot, 'download', fail)
    with pytest.raises(OSError):
        boot.setup(root)
    attempt = next((root / '.downloads').iterdir())
    deliver(monkeypatch, raw)
    assert boot.setup(root)['status'] == 'CREATED'
    assert (attempt / 'download.partial').read_bytes() == b'partial'


@pytest.mark.parametrize('name', ['schemas/CloudformationSchema.zip', 'schemas/manifest.json', 'catalog.json',
                                  'rules/ledger.json', 'rules/references.json', 'reconciliation.json', 'generation.json'])
def test_existing_corrupt_cache_is_never_replaced(release, monkeypatch, name):
    root, raw, lock = release
    deliver(monkeypatch, raw)
    boot.setup(root)
    assert boot.resolve_schema_dir(root).is_dir()
    target = root / '.cache' / lock['zip_sha256'] / name
    target.write_bytes(b'corrupt')
    monkeypatch.setattr(boot, 'download', lambda *_: pytest.fail('corrupt cache must not be silently refreshed'))
    with pytest.raises((ValueError, OSError)):
        boot.setup(root)
    with pytest.raises((ValueError, OSError)):
        boot.resolve_schema_dir(root)
    assert target.read_bytes() == b'corrupt'


def test_missing_cache_and_changed_catalog_or_inputs_fail(release, monkeypatch):
    root, raw, lock = release
    with pytest.raises(boot.SchemaSetupError):
        boot.setup(root, check_only=True)
    with pytest.raises(boot.SchemaSetupError):
        boot.resolve_schema_dir(root)
    lock['catalog_sha256'] = '0' * 64
    (root / 'schema-lock.json').write_bytes(boot.encode(lock))
    # A same-size rewrite can keep the (size, mtime, ctime, inode) fingerprint
    # within one filesystem timestamp tick; this test is about the changed hash.
    boot._lock.cache_clear()
    deliver(monkeypatch, raw)
    with pytest.raises(boot.SchemaSetupError, match='catalog differs'):
        boot.setup(root)
    assert not (root / '.cache' / lock['zip_sha256']).exists()
    (root.parent / 'rules/ledger.json').write_bytes(b'changed')
    with pytest.raises(boot.SchemaSetupError, match='Rule inputs changed'):
        boot.setup(root)


def test_existing_incomplete_directory_and_other_version_are_preserved(release, monkeypatch):
    root, raw, lock = release
    old = root / '.cache' / ('1' * 64)
    old.mkdir(parents=True)
    (old / 'user.txt').write_text('keep', encoding='utf-8')
    active = root / '.cache' / lock['zip_sha256']
    active.mkdir()
    monkeypatch.setattr(boot, 'download', lambda *_: pytest.fail('incomplete cache must not be replaced'))
    with pytest.raises((OSError, ValueError)):
        boot.setup(root)
    assert active.is_dir() and not list(active.iterdir())
    assert (old / 'user.txt').read_text(encoding='utf-8') == 'keep'


@pytest.mark.parametrize('name', ['../escape.json', '/escape.json', 'dir/escape.json', 'C:/escape.json',
                                  'dir\\escape.json', 'AWS-TEST.json'])
def test_archive_path_traversal_rejected_without_extraction(name, tmp_path):
    raw = zipped([(name, {'typeName': 'AWS::Test::Thing', 'properties': {}})])
    with pytest.raises(boot.SchemaSetupError, match='Unsafe'):
        boot.validate_archive(raw)
    assert not list(tmp_path.iterdir())


def test_archive_duplicates_symlinks_corruption_and_limits(monkeypatch):
    value = {'typeName': 'AWS::Test::Thing', 'properties': {}}
    with pytest.raises(boot.SchemaSetupError):
        boot.validate_archive(zipped([('a.json', value), ('b.json', value)]))
    link = zipfile.ZipInfo('link.json')
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(boot.SchemaSetupError):
        boot.validate_archive(zipped([(link, b'../outside')]))
    with pytest.raises(boot.SchemaSetupError):
        boot.validate_archive(b'PK truncated')
    raw = zipped([('a.json', value)])
    monkeypatch.setattr(boot, 'MAX_EXPANDED', 1)
    with pytest.raises(boot.SchemaSetupError, match='expansion limits'):
        boot.validate_archive(raw)


def test_nonofficial_source_lock_rejected(release):
    root, _, lock = release
    lock['source'] = 'https://example.invalid/archive.zip'
    (root / 'schema-lock.json').write_bytes(boot.encode(lock))
    with pytest.raises(boot.SchemaSetupError, match='non-official'):
        boot.setup(root)


def test_redirect_is_not_followed():
    with pytest.raises(boot.SchemaSetupError, match='redirected'):
        boot.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.invalid')


def test_legacy_updater_cannot_overwrite_release_or_cache(release, monkeypatch):
    from aws_design_sheet.schemas import pin, update
    root, raw, lock = release
    monkeypatch.setattr('urllib.request.urlopen', lambda *_args, **_kwargs: pytest.fail('must reject before network'))
    before = (root / 'schema-lock.json').read_bytes()
    for destination in (root, root / '.cache' / lock['zip_sha256'] / 'schemas'):
        with pytest.raises(ValueError, match='immutable'):
            update('ap-northeast-1', destination)
        with pytest.raises(ValueError, match='immutable'):
            pin(raw, lock['source'], lock['region'], destination)
    assert (root / 'schema-lock.json').read_bytes() == before
    assert not (root / '.cache').exists()


def drift_lock(root, raw, lock, tmp_path):
    """A format-3 us-east-1 lock reviewed against the fixture archive."""
    _, schemas = boot.validate_archive(raw)
    east = {**lock, 'format_version': 3, 'acquisition': boot.DRIFT_POLICY, 'region': 'us-east-1', 'baseline_region': 'ap-northeast-1',
            'source': 'https://schema.cloudformation.us-east-1.amazonaws.com/CloudformationSchema.zip',
            'reviewed_type_sha256': {t: _digest(s) for t, s in sorted(schemas.items())}}
    preview = tmp_path / 'drift-preview'
    preview.mkdir()
    east.update(boot.generate_bundle(raw, preview, root, east))
    (root / 'schema-lock.us-east-1.json').write_bytes(boot.encode(east))
    return east


def drifted(raw):
    """One changed and one added type, as AWS does between daily rebuilds."""
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = [(i.filename, json.loads(archive.read(i))) for i in archive.infolist()]
    entries[0][1]['properties']['Added'] = {'type': 'string'}
    kind = entries[1][1]['typeName'].rsplit('::', 1)[0] + '::Extra'
    entries.append(('aws-extra-fixture.json', {'typeName': kind, 'properties': {'Name': {'type': 'string'}}, 'additionalProperties': False}))
    return zipped(entries), entries[0][1]['typeName'], kind


def test_format_three_exact_archive_is_reviewed_exact(release, monkeypatch, tmp_path):
    root, raw, lock = release
    drift_lock(root, raw, lock, tmp_path)
    deliver(monkeypatch, raw)
    result = boot.setup(root, region='us-east-1')
    assert result['status'] == 'CREATED' and result['review_status'] == 'REVIEWED_EXACT'
    assert result['review_drift'] == {'added': 0, 'removed': 0, 'changed': 0}
    monkeypatch.setattr(boot, 'download', lambda *_: pytest.fail('offline cache contacted network'))
    assert boot.setup(root, region='us-east-1', check_only=True)['review_status'] == 'REVIEWED_EXACT'


def test_newer_official_archive_is_accepted_with_recorded_drift(release, monkeypatch, tmp_path):
    from aws_design_sheet.document_catalog import Catalog
    root, raw, lock = release
    east = drift_lock(root, raw, lock, tmp_path)
    newer, changed, added = drifted(raw)
    deliver(monkeypatch, newer)
    result = boot.setup(root, region='us-east-1')
    assert result['status'] == 'CREATED' and result['review_status'] == 'DRIFTED_FROM_REVIEWED'
    assert result['review_drift'] == {'added': 1, 'removed': 0, 'changed': 1}
    assert result['zip_sha256'] == boot.digest(newer) != east['zip_sha256']
    bundle = Path(result['schema_dir']).parent
    assert bundle == boot.bundle_path(root, east, boot.digest(newer))
    drift = json.loads((bundle / 'drift.json').read_text(encoding='utf-8'))
    assert drift['changed'] == [changed] and drift['added'] == [added] and drift['reviewed_zip_sha256'] == east['zip_sha256']
    reconciliation = json.loads((bundle / 'reconciliation.json').read_text(encoding='utf-8'))
    assert changed in reconciliation['changed'] and added in reconciliation['added']
    ledger = json.loads((bundle / 'rules/ledger.json').read_text(encoding='utf-8'))
    assert ledger['types'][added]['state'] == 'UNRESEARCHED' and ledger['schema_zip_sha256'] == boot.digest(newer)
    monkeypatch.setattr(boot, 'download', lambda *_: pytest.fail('offline cache contacted network'))
    assert boot.setup(root, region='us-east-1', check_only=True)['review_status'] == 'DRIFTED_FROM_REVIEWED'
    assert boot.resolve_schema_dir(root, 'us-east-1') == Path(result['schema_dir'])
    assert Catalog(root, region='us-east-1').manifest['review_status'] == 'DRIFTED_FROM_REVIEWED'


@pytest.mark.parametrize('target', ['drift', 'receipt', 'catalog'])
def test_tampered_drift_cache_is_rejected(release, monkeypatch, tmp_path, target):
    root, raw, lock = release
    drift_lock(root, raw, lock, tmp_path)
    newer, _, _ = drifted(raw)
    deliver(monkeypatch, newer)
    bundle = Path(boot.setup(root, region='us-east-1')['schema_dir']).parent
    if target == 'drift':
        value = json.loads((bundle / 'drift.json').read_text());value['changed'] = []
        (bundle / 'drift.json').write_bytes(boot.encode(value))
    elif target == 'receipt':
        value = json.loads((bundle / 'generation.json').read_text());value['generated']['catalog_sha256'] = '0' * 64
        (bundle / 'generation.json').write_bytes(boot.encode(value))
    else:
        (bundle / 'catalog.json').write_bytes(b'{}')
    boot._verified.cache_clear()
    with pytest.raises(boot.SchemaSetupError):
        boot.resolve_schema_dir(root, 'us-east-1')


def test_older_lock_formats_still_refuse_a_changed_archive(release, monkeypatch, tmp_path):
    root, raw, lock = release
    regional_lock(root, raw, lock, tmp_path)
    newer, _, _ = drifted(raw)
    deliver(monkeypatch, newer)
    with pytest.raises(boot.SchemaSetupError, match='Official URL content changed'):
        boot.setup(root, region='us-east-1')


def test_several_drift_caches_for_one_lock_are_ambiguous(release, monkeypatch, tmp_path):
    root, raw, lock = release
    east = drift_lock(root, raw, lock, tmp_path)
    newer, _, _ = drifted(raw)
    deliver(monkeypatch, newer)
    bundle = Path(boot.setup(root, region='us-east-1')['schema_dir']).parent
    shutil.copytree(bundle, boot.bundle_path(root, east, 'f' * 64))
    boot._verified.cache_clear()
    with pytest.raises(boot.SchemaSetupError, match='Several schema caches'):
        boot.resolve_schema_dir(root, 'us-east-1')


def test_format_three_lock_requires_reviewed_type_fingerprints(release, tmp_path):
    root, raw, lock = release
    east = drift_lock(root, raw, lock, tmp_path)
    east.pop('reviewed_type_sha256')
    (root / 'schema-lock.us-east-1.json').write_bytes(boot.encode(east))
    with pytest.raises(boot.SchemaSetupError, match='reviewed type'):
        boot.read_lock(root, 'us-east-1')
