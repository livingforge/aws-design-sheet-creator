"""Recorded re-reviews: exact schema fingerprints keep a reviewed state; anything else re-opens it."""
import copy
import io
import json
import zipfile

import pytest

from aws_design_sheet import schema_bootstrap as boot
from aws_design_sheet import schema_reviews as reviews
from aws_design_sheet.schema_diff import _digest, reconcile_from_hashes

URL = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/resource-type-schemas.html'
SCHEMAS = {f'AWS::{n}::Fixture': {'typeName': f'AWS::{n}::Fixture', 'properties': {'Name': {'type': 'string'}},
                                  'additionalProperties': False} for n in ('EC2', 'S3', 'SQS')}


def zipped(schemas):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for name, schema in schemas.items():archive.writestr(f"aws-{name.split('::')[1].lower()}-fixture.json", json.dumps(schema))
    return stream.getvalue()


def reviewed(name):
    return {'service': name.split('::')[1], 'state': 'REVIEWED_NO_ADDITIONAL_RULES', 'source_urls': [URL],
            'rule_ids': [], 'open_questions': [], 'reviewed_at': '2026-10-01', 'rationale': 'fixture'}


def ledger(schemas):
    return {'ledger_version': '1.0.0', 'schema_region': 'ap-northeast-1', 'schema_zip_sha256': boot.digest(zipped(schemas)),
            'types': {name: reviewed(name) for name in schemas}}


def batch(kind='REGIONAL_APPLICABILITY', region='us-east-1', types=None, **extra):
    value = {'id': 'fixture-review', 'kind': kind, 'region': region, 'reviewed_at': '2026-10-21', 'reviewer': 'fixture reviewer',
             'method': 'fixture', 'rationale': 'fixture', 'source_urls': [URL], 'types': types or {}}
    if kind == 'REGIONAL_APPLICABILITY':value['baseline_region'] = 'ap-northeast-1'
    value.update(extra)
    return value


def release(tmp_path, records):
    root = tmp_path / 'package';schemas = root / 'schemas';(root / 'rules').mkdir(parents=True);schemas.mkdir()
    (root / 'pyproject.toml').write_text('[project]\nversion="0.4.0"\n', encoding='utf-8')
    assets = {'ledger.json': ledger(SCHEMAS), 'ruleset.json': {'ruleset_version': '1.0.0', 'rules': []},
              'references.json': {'catalog_version': '1.0.0', 'references': []}, 'schema-reviews.json': records}
    for name, value in assets.items():(root / 'rules' / name).write_bytes(boot.encode(value))
    raw = zipped(SCHEMAS)
    lock = {'format_version': 3, 'acquisition': boot.DRIFT_POLICY, 'region': 'us-east-1', 'baseline_region': 'ap-northeast-1',
            'tool_version': '0.4.0', 'source': 'https://schema.cloudformation.us-east-1.amazonaws.com/CloudformationSchema.zip',
            'zip_sha256': boot.digest(raw), 'reviewed_at': '2026-10-21T00:00:00+00:00',
            'previous_type_sha256': {t: _digest(s) for t, s in SCHEMAS.items()},
            'reviewed_type_sha256': {t: _digest(s) for t, s in SCHEMAS.items()},
            'input_sha256': {n: boot.digest((root / 'rules' / n).read_bytes()) for n in assets}}
    stage = tmp_path / 'stage';stage.mkdir()
    boot.generate_bundle(raw, stage, schemas, lock)
    return (json.loads((stage / 'rules/ledger.json').read_text(encoding='utf-8')),
            json.loads((stage / 'reconciliation.json').read_text(encoding='utf-8')))


def test_regional_record_keeps_exactly_the_reviewed_types(tmp_path):
    ec2 = 'AWS::EC2::Fixture';digest = _digest(SCHEMAS[ec2])
    records = {'format_version': 1, 'reviews': [batch(types={ec2: {'type_sha256': digest, 'baseline_type_sha256': digest}})]}
    result, changes = release(tmp_path, records)
    assert result['types'][ec2] == reviewed(ec2)
    for other in ('AWS::S3::Fixture', 'AWS::SQS::Fixture'):
        assert result['types'][other]['state'] == 'REVIEW_REQUIRED'
        assert result['types'][other]['open_questions'] == [reviews.REGIONAL_QUESTION.format(region='us-east-1', baseline='ap-northeast-1')]
    assert changes['regional_review_accepted'] == [ec2] and ec2 not in changes['regional_review_required']


@pytest.mark.parametrize('change', ['fingerprint', 'region', 'baseline', 'kind'])
def test_a_record_for_anything_else_leaves_the_question(tmp_path, change):
    ec2 = 'AWS::EC2::Fixture';digest = _digest(SCHEMAS[ec2])
    record = batch(types={ec2: {'type_sha256': digest, 'baseline_type_sha256': digest}})
    if change == 'fingerprint':record['types'][ec2]['type_sha256'] = '0' * 64
    elif change == 'region':record['region'] = 'ap-northeast-3'
    elif change == 'baseline':record['baseline_region'] = 'eu-west-1'
    else:record = batch('SCHEMA_CHANGE', types={ec2: {'type_sha256': digest, 'previous_type_sha256': digest}})
    result, changes = release(tmp_path, {'format_version': 1, 'reviews': [record]})
    assert result['types'][ec2]['state'] == 'REVIEW_REQUIRED' and 'regional_review_accepted' not in changes


def test_schema_change_record_needs_the_exact_new_fingerprint_and_intact_bases(tmp_path):
    name = 'AWS::EC2::Fixture';old = SCHEMAS[name]
    new = copy.deepcopy(old);new['properties']['Extra'] = {'type': 'string'}
    rules = tmp_path / 'rules';rules.mkdir()

    def reconcile(accepted):
        (rules / 'ledger.json').write_bytes(boot.encode({**ledger({name: old}), 'types': {name: reviewed(name)}}))
        (rules / 'ruleset.json').write_bytes(boot.encode({'ruleset_version': '1.0.0', 'rules': []}))
        report = reconcile_from_hashes(rules, {name: _digest(old)}, {name: new},
                                       {'region': 'ap-northeast-1', 'zip_sha256': '1' * 64}, '2026-10-21', accepted)
        return report, json.loads((rules / 'ledger.json').read_text(encoding='utf-8'))['types'][name]
    report, entry = reconcile(None)
    assert entry['state'] == 'UNRESEARCHED' and report['reset'] == [name]
    report, entry = reconcile({name: '0' * 64})
    assert entry['state'] == 'UNRESEARCHED'
    report, entry = reconcile({name: _digest(new)})
    assert entry == reviewed(name) and report['schema_review_accepted'] == [name] and report['reset'] == []


@pytest.mark.parametrize('mutate,message', [
    (lambda r: r['reviews'].append(copy.deepcopy(r['reviews'][0])), 'unique'),
    (lambda r: r['reviews'][0].update(source_urls=['https://example.com/x']), 'AWS HTTPS'),
    (lambda r: r['reviews'][0].update(baseline_region='us-east-1'), 'different baseline'),
    (lambda r: r['reviews'][0].update(reviewer=' '), 'reviewer'),
    (lambda r: r['reviews'][0]['types']['AWS::EC2::Fixture'].update(type_sha256='x'), 'fingerprint'),
    (lambda r: r['reviews'][0]['types']['AWS::EC2::Fixture'].pop('baseline_type_sha256'), 'baseline_type_sha256'),
])
def test_records_must_be_attributable_and_exact(mutate, message):
    digest = _digest(SCHEMAS['AWS::EC2::Fixture'])
    records = {'format_version': 1, 'reviews': [batch(types={'AWS::EC2::Fixture': {'type_sha256': digest, 'baseline_type_sha256': digest}})]}
    reviews.validate(copy.deepcopy(records))
    mutate(records)
    with pytest.raises(ValueError, match=message):reviews.validate(records)


def test_queue_routes_regional_wording_and_changed_schemas_to_a_person():
    changed = copy.deepcopy(SCHEMAS['AWS::SQS::Fixture']);changed['properties']['Extra'] = {'type': 'string'}
    candidate = {**SCHEMAS, 'AWS::SQS::Fixture': changed}
    rule = {'id': 'S3.FIXTURE.REGION', 'source_type': 'AWS::S3::Fixture', 'description': 'Only valid in the bucket Region',
            'source_urls': [URL]}
    queue = reviews.queue(ledger(SCHEMAS), {'rules': [rule]}, {'references': []}, reviews.empty(),
                          region='ap-northeast-3', baseline_region='ap-northeast-1',
                          previous={t: _digest(s) for t, s in SCHEMAS.items()}, schemas=candidate, old_schemas=SCHEMAS)
    rows = {r['type']: r for r in queue['types']}
    assert rows['AWS::EC2::Fixture']['regional_review'] == 'CARRY_OVER_CANDIDATE'
    assert rows['AWS::S3::Fixture']['regional_review'] == 'REGIONAL_TERMS' and rows['AWS::S3::Fixture']['regional_terms'] == ['rule:S3.FIXTURE.REGION']
    assert rows['AWS::SQS::Fixture']['regional_review'] == 'SCHEMA_CHANGED'
    assert rows['AWS::SQS::Fixture']['property_diff']['added_properties'] == ['Extra']
    recorded = reviews.record(reviews.empty(), queue, kind='REGIONAL_APPLICABILITY', select='CARRY_OVER_CANDIDATE',
                              review_id='osaka-fixture', reviewer='fixture reviewer', method='m', rationale='r',
                              source_urls=[URL], reviewed_at='2026-10-21')
    assert list(recorded['reviews'][0]['types']) == ['AWS::EC2::Fixture']
    with pytest.raises(ValueError, match='not in the selected queue category'):
        reviews.record(reviews.empty(), queue, kind='REGIONAL_APPLICABILITY', select='CARRY_OVER_CANDIDATE',
                       review_id='x', reviewer='r', method='m', rationale='r', source_urls=[URL],
                       reviewed_at='2026-10-21', types=['AWS::S3::Fixture'])
    again = reviews.queue(ledger(SCHEMAS), {'rules': [rule]}, {'references': []}, recorded,
                          region='ap-northeast-3', baseline_region='ap-northeast-1',
                          previous={t: _digest(s) for t, s in SCHEMAS.items()}, schemas=candidate)
    assert 'AWS::EC2::Fixture' not in {r['type'] for r in again['types']}


def test_review_causes_are_read_from_ledger_questions():
    assert reviews.cause(reviews.REGIONAL_QUESTION.format(region='ap-northeast-3', baseline='ap-northeast-1')) == 'REGIONAL_APPLICABILITY'
    assert reviews.cause(reviews.SCHEMA_QUESTION.format(date='2026-10-21')) == 'SCHEMA_CHANGE'
    assert reviews.cause('Quota depends on the account') == 'OPEN_QUESTION'


def test_repository_records_bind_osaka_carry_overs_to_the_locked_archive():
    root = boot.ROOT
    records = reviews.load(root / 'rules')
    osaka = [r for r in records['reviews'] if r['region'] == 'ap-northeast-3']
    assert osaka and all(r['kind'] == 'REGIONAL_APPLICABILITY' and r['baseline_region'] == 'ap-northeast-1' for r in osaka)
    lock = boot.read_lock(root / 'schemas', 'ap-northeast-3')
    for review in osaka:
        for name, binding in review['types'].items():
            assert lock['previous_type_sha256'][name] == binding['baseline_type_sha256'] == binding['type_sha256'], name
            assert binding['type_sha256'] == lock['reviewed_type_sha256'][name], name
