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
