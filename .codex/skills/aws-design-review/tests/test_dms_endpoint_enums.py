import pytest
from aws_design_sheet.checks.dms.endpoint_enums import evaluate_dms_endpoint_enums, ENUMS, AMBIGUOUS
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def evaluate(path, raw, **settings):
    parts = path.split('/')
    props = {parts[0]: raw} if len(parts) == 1 else {parts[0]: {parts[1]: raw, **settings}}
    r = target('endpoint', 'AWS::DMS::Endpoint', **props)
    return [f for f in evaluate_dms_endpoint_enums(linked_design(r),r) if f['path'] == '/properties/'+path]


def activation(path):
    if '/DatePartition' in path:
        return {'DatePartitionEnabled': True}
    if path.endswith(('/EncodingType','/ParquetVersion')):
        return {'DataFormat': 'parquet'}
    return {}


@pytest.mark.parametrize('path,raw', [(p,v) for p,vs in ENUMS.items() for v in vs])
def test_documented_values(path,raw):
    assert evaluate(path,raw,**activation(path))[0]['verdict'] == 'PASS'


@pytest.mark.parametrize('path', list(ENUMS))
@pytest.mark.parametrize('raw,want', [('invalid','FAIL'), ('','NEEDS_REVIEW'), (UNKNOWN,'NEEDS_REVIEW')])
def test_invalid_or_unresolved(path,raw,want):
    assert evaluate(path,raw,**activation(path))[0]['verdict'] == want


@pytest.mark.parametrize('path,raw', [(p,v) for p,vs in AMBIGUOUS.items() for v in vs])
def test_conflicting_prose_spelling(path,raw):
    assert evaluate(path,raw,**activation(path))[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('enabled,want', [(False,'NOT_APPLICABLE'),(UNKNOWN,'NEEDS_REVIEW')])
def test_date_partition_activation(enabled,want):
    assert evaluate('S3Settings/DatePartitionDelimiter','invalid',DatePartitionEnabled=enabled)[0]['verdict'] == want


@pytest.mark.parametrize('fmt,want', [('csv','NOT_APPLICABLE'),(UNKNOWN,'NEEDS_REVIEW')])
def test_parquet_activation(fmt,want):
    assert evaluate('S3Settings/ParquetVersion','invalid',DataFormat=fmt)[0]['verdict'] == want


def test_omission_and_unknown_ancestor():
    r = target('endpoint','AWS::DMS::Endpoint')
    assert evaluate_dms_endpoint_enums(linked_design(r),r) == []
    r = target('endpoint','AWS::DMS::Endpoint',S3Settings=UNKNOWN)
    assert all(f['verdict']=='NEEDS_REVIEW' for f in evaluate_dms_endpoint_enums(linked_design(r),r))


def test_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root = Path(__file__).resolve().parents[1]
    r = target('endpoint','AWS::DMS::Endpoint',SslMode='invalid')
    findings = Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='DMS_ENDPOINT_DOCUMENTED_ENUMS' and f['verdict']=='FAIL' for f in findings)
