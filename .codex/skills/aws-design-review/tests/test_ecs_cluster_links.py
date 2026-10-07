import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('field',['KmsKeyId','FargateEphemeralStorageKmsKeyId'])
@pytest.mark.parametrize('multi,expected',[(True,'FAIL'),(False,'PASS'),(UNKNOWN,'NEEDS_REVIEW'),(None,'PASS')])
def test_storage_key_region_type(field,multi,expected):
    resource = target('cluster','AWS::ECS::Cluster',Configuration={'ManagedStorageConfiguration':{field:{'Ref':'key'}}})
    key = target('key','AWS::KMS::Key',**({'MultiRegion':multi} if multi is not None else {}))
    data = linked_design(resource,[key],[(f'Configuration/ManagedStorageConfiguration/{field}','key')])
    findings = {r['rule_id']:r['verdict'] for r in run_resource_checks(data,resource)}
    assert findings['ECS_CLUSTER_STORAGE_SINGLE_REGION'] == expected


@pytest.mark.parametrize('name,expected',[
    ('','PASS'),('namespace','PASS'),('a'*1024,'PASS'),('a'*1025,'FAIL'),
    ('a/b','FAIL'),('a>b','FAIL'),('a<b','FAIL'),('a"b','FAIL'),
    (UNKNOWN,'NEEDS_REVIEW'),('arn:unknown/namespace','NEEDS_REVIEW'),
],ids=['remove','name','max','over','slash','greater','less','quote','unknown','future-arn'])
def test_namespace_name(name,expected):
    resource = target('cluster','AWS::ECS::Cluster',ServiceConnectDefaults={'Namespace':name})
    findings = {r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(resource),resource)}
    assert findings['ECS_CLUSTER_NAMESPACE_NAME'] == expected


@pytest.mark.parametrize('region,account,expected',[
    ('ap-northeast-1','123456789012','PASS'),('us-west-2','123456789012','FAIL'),
    ('ap-northeast-1','999999999999','FAIL'),
])
def test_namespace_arn_scope(region,account,expected):
    resource = target('cluster','AWS::ECS::Cluster',ServiceConnectDefaults={'Namespace':f'arn:aws:servicediscovery:{region}:{account}:namespace/ns-123'})
    resource.scope.account = '123456789012'
    findings = {r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(resource),resource)}
    assert findings['ECS_CLUSTER_NAMESPACE_SCOPE'] == expected
    assert 'ECS_CLUSTER_NAMESPACE_NAME' not in findings
