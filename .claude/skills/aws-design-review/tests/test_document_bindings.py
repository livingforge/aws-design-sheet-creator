"""Local EXTERNAL_REF bindings: shape-checked values for evaluation only, never secrets, never fetched."""
import json
from pathlib import Path

import pytest

from aws_design_sheet.document_cli import main

EXAMPLE = Path(__file__).resolve().parents[1] / 'examples/basic-design/input.json'
ARN = 'arn:aws:kms:ap-northeast-1:111122223333:key/11111111-2222-3333-4444-555555555555'


def write(tmp_path, bindings, name='bindings.json', **extra):
    path = tmp_path / name
    path.write_text(json.dumps({'binding_version': '1.0', 'bindings': bindings, **extra}), encoding='utf-8')
    return path


def run(tmp_path, bindings_path, *args):
    out = tmp_path / 'generated'
    code = main([str(EXAMPLE), '--environment', 'prod', '--output', str(out), *args,
                 *(['--external-bindings', str(bindings_path)] if bindings_path else [])])
    return code, out


def test_bound_values_reach_the_evaluation_and_mismatches_stay_unknown(tmp_path):
    path = write(tmp_path, [{'ref': 'kms-key-alias/portal', 'value': 'alias/portal-assets-cmk', 'source': 'existing key list'},
                            {'ref': 'kms-key-arn/portal-logs', 'value': 12345},
                            {'ref': 'not-used', 'value': 'vpc-0123456789abcdef0'}])
    code, out = run(tmp_path, path, '--evaluate')
    assert code in (0, 3)
    report = json.loads((out / 'review-report.json').read_text(encoding='utf-8'))
    bindings = report['external_bindings']
    assert bindings['status'] == 'PROVIDED' and bindings['counts'] == {'BOUND': 1, 'SHAPE_MISMATCH': 1}
    assert bindings['unused_refs'] == ['not-used']
    reasons = {r['reason_code'] for r in report['unresolved'] if r['mode'] == 'EXTERNAL_REF'}
    assert reasons == {'EXTERNAL_VALUE_BOUND_LOCALLY', 'EXTERNAL_BINDING_SHAPE_MISMATCH'}
    evaluation = json.loads((out / 'evaluation.json').read_text(encoding='utf-8'))
    bound = [c for c in evaluation['coverage'] if c['kind'] == 'EXTERNAL_VALUE_BOUND']
    assert [c['path'] for c in bound] == ['/properties/BucketEncryption/ServerSideEncryptionConfiguration/0/ServerSideEncryptionByDefault/KMSMasterKeyID']
    assert any(c['kind'] == 'BRIDGE_UNKNOWN_VALUE' and c['reason'] == 'EXTERNAL_REF_BINDING_SHAPE_MISMATCH' for c in evaluation['coverage'])
    assert evaluation['provenance']['external_bindings_sha256'] == bindings['sha256']
    design = json.loads((out / 'design.json').read_text(encoding='utf-8'))
    # The design keeps the reference; the bound value is evaluation input only.
    assert 'alias/portal-assets-cmk' not in json.dumps(design['design'])
    assert json.loads((out / 'summary.json').read_text(encoding='utf-8'))['external_bindings'] == bindings['counts']


def test_valid_arn_binding_is_used(tmp_path):
    path = write(tmp_path, [{'ref': 'kms-key-arn/portal-logs', 'value': ARN}], environment='prod')
    code, out = run(tmp_path, path)
    assert code == 0
    report = json.loads((out / 'review-report.json').read_text(encoding='utf-8'))
    assert report['external_bindings']['counts'] == {'BOUND': 1, 'UNBOUND': 1}


def test_without_bindings_nothing_is_assumed(tmp_path):
    code, out = run(tmp_path, None)
    report = json.loads((out / 'review-report.json').read_text(encoding='utf-8'))
    assert report['external_bindings']['status'] == 'NOT_PROVIDED'
    assert {r['reason_code'] for r in report['unresolved'] if r['mode'] == 'EXTERNAL_REF'} == {'EXTERNAL_VALUE_NOT_RESOLVED'}


@pytest.mark.parametrize('bindings,extra,code_prefix', [
    ([{'ref': 'kms-key-alias/portal', 'value': 'AKIA' + 'ABCDEFGHIJKLMNOP'}], {}, 'SECRET_LIKE_BINDING'),
    ([{'ref': 'x', 'value': 'a'}, {'ref': 'x', 'value': 'b'}], {}, 'DUPLICATE_BINDING'),
    ([{'ref': 'x', 'value': None}], {}, 'INVALID_BINDING'),
    ([{'ref': 'x', 'value': 'a'}], {'environment': 'dev'}, 'BINDING_ENVIRONMENT_MISMATCH'),
])
def test_invalid_binding_files_stop_before_outputs(tmp_path, capsys, bindings, extra, code_prefix):
    code, out = run(tmp_path, write(tmp_path, bindings, **extra))
    assert code == 2 and not out.exists()
    printed = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert printed['generation_status'] == 'BINDING_ERROR' and printed['error_code'].startswith(code_prefix)
    assert 'ABCDEFGHIJKLMNOP' not in json.dumps(printed)


def test_secret_reference_is_never_bound(tmp_path, capsys):
    data = json.loads(EXAMPLE.read_text(encoding='utf-8'))
    logs = next(r for r in data['resources'] if r['type'] == 'AWS::Logs::LogGroup')
    logs['settings']['KmsKeyId'] = {'mode': 'SECRET_REF', 'classification': 'SECRET', 'ref': 'secret://portal/kms'}
    source = tmp_path / 'input.json';source.write_text(json.dumps(data), encoding='utf-8')
    out = tmp_path / 'generated'
    code = main([str(source), '--environment', 'prod', '--output', str(out),
                 '--external-bindings', str(write(tmp_path, [{'ref': 'secret://portal/kms', 'value': 'alias/x'}]))])
    assert code == 2 and not out.exists()
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])['error_code'].startswith('SECRET_REFERENCE_CANNOT_BE_BOUND')


@pytest.mark.parametrize('kind,path,value,region,expected', [
    ('AWS::Logs::LogGroup', '/properties/KmsKeyId', ARN, 'ap-northeast-1', None),
    ('AWS::Logs::LogGroup', '/properties/KmsKeyId', ARN, 'ap-northeast-3', 'REFUSED'),
    ('AWS::Logs::LogGroup', '/properties/KmsKeyId', 'arn:aws-cn:kms:cn-north-1:111122223333:key/x', 'ap-northeast-1', 'REFUSED'),
    ('AWS::S3::Bucket', '/properties/NotificationConfiguration/TopicConfigurations/0/Topic', 'arn:aws:s3:::example-bucket', 'ap-northeast-3', None),
    ('AWS::EC2::Instance', '/properties/IamInstanceProfile', 'arn:aws:iam::111122223333:instance-profile/x', 'ap-northeast-3', None),
    ('AWS::CloudFront::Distribution', '/properties/DistributionConfig/ViewerCertificate/AcmCertificateArn',
     'arn:aws:acm:us-east-1:111122223333:certificate/x', 'ap-northeast-1', None),
    ('AWS::CloudFront::Distribution', '/properties/DistributionConfig/ViewerCertificate/AcmCertificateArn',
     'arn:aws:acm:ap-northeast-1:111122223333:certificate/x', 'ap-northeast-1', 'REFUSED'),
    ('AWS::Backup::BackupPlan', '/properties/BackupPlan/BackupPlanRule/0/CopyActions/0/DestinationBackupVaultArn',
     'arn:aws:backup:ap-northeast-3:111122223333:backup-vault:dr', 'ap-northeast-1', 'BY_DESIGN'),
    ('AWS::Lambda::Function', '/properties/Layers', ['arn:aws:lambda:ap-northeast-1:111122223333:layer:x:1',
                                                     'arn:aws:lambda:us-west-2:111122223333:layer:y:1'], 'ap-northeast-1', 'REFUSED'),
])
def test_arn_regions_follow_the_resource_unless_the_property_says_otherwise(kind, path, value, region, expected):
    from aws_design_sheet.document_bindings import region_check
    result = region_check(kind, path, value, region)
    if expected is None:assert result is None
    else:assert result and result['cross_region_by_design'] == (expected == 'BY_DESIGN')


def test_tokyo_key_is_not_used_for_an_osaka_resource(tmp_path):
    data = json.loads(EXAMPLE.read_text(encoding='utf-8'))
    for env in data['environments']:env['region'] = 'ap-northeast-3'
    source = tmp_path / 'input.json';source.write_text(json.dumps(data), encoding='utf-8')
    out = tmp_path / 'generated'
    path = write(tmp_path, [{'ref': 'kms-key-arn/portal-logs', 'value': ARN}])
    assert main([str(source), '--environment', 'prod', '--output', str(out), '--evaluate', '--external-bindings', str(path)]) in (0, 3)
    report = json.loads((out / 'review-report.json').read_text(encoding='utf-8'))
    use = next(u for u in json.loads((out / 'design.json').read_text(encoding='utf-8'))['external_bindings']['uses']
               if u['ref'] == 'kms-key-arn/portal-logs')
    assert use['status'] == 'REGION_MISMATCH' and use['region']['expected_region'] == 'ap-northeast-3'
    assert use['region']['found'] == [{'arn_partition': 'aws', 'arn_region': 'ap-northeast-1'}] and 'value' not in use
    assert report['external_bindings']['counts'] == {'REGION_MISMATCH': 1, 'UNBOUND': 1}
    assert 'EXTERNAL_BINDING_REGION_MISMATCH' in {r['reason_code'] for r in report['unresolved']}
    evaluation = json.loads((out / 'evaluation.json').read_text(encoding='utf-8'))
    assert any(c['kind'] == 'BRIDGE_UNKNOWN_VALUE' and c['reason'] == 'EXTERNAL_REF_BINDING_REGION_MISMATCH' for c in evaluation['coverage'])
    assert not any(c['kind'] == 'EXTERNAL_VALUE_BOUND' for c in evaluation['coverage'])
