import pytest
from aws_design_sheet.checks.multi_service.named_resource_collisions import NAMES, KEYS, finite_ledger_checks
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def properties(paths, name='example'):
    result = {}
    for path in paths:
        node = result
        for part in path.split('/')[:-1]: node = node.setdefault(part, {})
        node[path.split('/')[-1]] = '/' if path == 'Path' else name
    return result


@pytest.mark.parametrize('kind', list(NAMES))
@pytest.mark.parametrize('variation,expected', [('same','FAIL'),('account','NEEDS_REVIEW'),
    ('region','NEEDS_REVIEW'),('environment','NEEDS_REVIEW'),('alone','NEEDS_REVIEW')])
def test_collision_scope(kind, variation, expected):
    rule, paths, _ = NAMES[kind]
    resource = target('one',kind,**properties(paths))
    other = target('two',kind,**properties(paths))
    if variation == 'account': other.scope.account='999999999999'
    if variation == 'region': other.scope.region='us-west-2'
    if variation == 'environment': other.scope.environment='other'
    design = linked_design(resource, [] if variation == 'alone' else [other])
    finding = next(f for f in run_resource_checks(design,resource) if f['rule_id']==rule)
    assert finding['verdict']==expected
    assert finding['severity']=='WARNING'


@pytest.mark.parametrize('kind',[kind for kind in NAMES if NAMES[kind][1]])
def test_unresolved_names(kind):
    rule, paths, _=NAMES[kind]
    resource=target('one',kind,**properties(paths,UNKNOWN))
    other=target('two',kind,**properties(paths,UNKNOWN))
    assert finite_ledger_checks(linked_design(resource,[other]),resource)[0]['verdict']=='NEEDS_REVIEW'


def test_mfa_default_path_and_distinct_paths():
    one=target('one','AWS::IAM::VirtualMFADevice',VirtualMfaDeviceName='device')
    two=target('two',one.type,VirtualMfaDeviceName='device',Path='/')
    assert finite_ledger_checks(linked_design(one,[two]),one)[0]['verdict']=='FAIL'
    two.fields[-1].selected().value='/other/'
    assert finite_ledger_checks(linked_design(one,[two]),one)[0]['verdict']=='NEEDS_REVIEW'


def test_cluster_parameter_lowercase():
    one=target('one','AWS::RDS::DBClusterParameterGroup',DBClusterParameterGroupName='Example')
    two=target('two',one.type,DBClusterParameterGroupName='example')
    assert finite_ledger_checks(linked_design(one,[two]),one)[0]['verdict']=='FAIL'


@pytest.mark.parametrize('kind',list(KEYS))
@pytest.mark.parametrize('key_properties,linked_flag,expected', [({},True,'PASS'),
    ({'KeySpec':'RSA_2048'},True,'FAIL'),({'KeyUsage':'SIGN_VERIFY'},True,'FAIL'),
    ({'KeySpec':UNKNOWN},True,'NEEDS_REVIEW'),({},False,'NEEDS_REVIEW')])
def test_linked_key_type(kind,key_properties,linked_flag,expected):
    rule,path,_=KEYS[kind]
    resource=target('resource',kind,**properties([path],'key'))
    key=target('key','AWS::KMS::Key',**key_properties)
    design=linked_design(resource,[key],[(path,'key')] if linked_flag else [])
    assert next(f['verdict'] for f in run_resource_checks(design,resource) if f['rule_id']==rule)==expected


@pytest.mark.parametrize('kind',list(KEYS))
def test_conditional_key(kind):
    rule,path,_=KEYS[kind]
    resource=target('resource',kind,**properties([path],'key'))
    key=target('key','AWS::KMS::Key')
    design=linked_design(resource,[key],[(path,'key')]);design.relations[0].condition='conditional'
    assert next(f['verdict'] for f in finite_ledger_checks(design,resource) if f['rule_id']==rule)=='NEEDS_REVIEW'
