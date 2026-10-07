import json
import pytest
from aws_design_sheet.checks.ssm.parameter_policies import parameter_policies
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN

EXP={'Type':'Expiration','Version':'1.0','Attributes':{'Timestamp':'2030-01-01T00:00:00Z'}}
NOTICE={'Type':'ExpirationNotification','Version':'1.0','Attributes':{'Before':'15','Unit':'Days'}}


def check(policies,tier='Advanced',raw=False):
    resource=target('parameter','AWS::SSM::Parameter',Policies=policies if raw else json.dumps(policies),**({'Tier':tier} if tier is not None else {}))
    return parameter_policies(linked_design(resource),resource)


@pytest.mark.parametrize('kind,expected',[('Expiration','PASS'),('ExpirationNotification','PASS'),
    ('NoChangeNotification','PASS'),('Unknown','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_types(kind,expected):
    assert next(f['verdict'] for f in check([{**EXP,'Type':kind}]) if f['rule_id']=='SSM_POLICY_TYPE')==expected


@pytest.mark.parametrize('policies,expected',[([EXP],'PASS'),([EXP,EXP],'FAIL'),([NOTICE,NOTICE],'PASS'),
    ([EXP,{'Type':UNKNOWN}],'NEEDS_REVIEW'),([EXP,EXP,{'Type':UNKNOWN}],'FAIL')])
def test_expiration_count(policies,expected):
    assert next(f['verdict'] for f in check(policies) if f['rule_id']=='SSM_POLICY_EXPIRATION_UNIQUE')==expected


@pytest.mark.parametrize('policy,expected',[(EXP,'PASS'),(NOTICE,'PASS'),
    ({**EXP,'Version':'2.0'},'NEEDS_REVIEW'),({**EXP,'Attributes':{}},'NEEDS_REVIEW'),
    ({**EXP,'Extra':'future'},'NEEDS_REVIEW'),
    ({'Type':'NoChangeNotification','Version':'1.0','Attributes':{'After':'20','Unit':'Hours'}},'PASS'),
    ({**NOTICE,'Attributes':{'Before':'-1','Unit':'Days'}},'NEEDS_REVIEW')])
def test_documented_shape(policy,expected):
    assert next(f['verdict'] for f in check([policy]) if f['rule_id']=='SSM_POLICY_DOCUMENTED_SHAPE')==expected


@pytest.mark.parametrize('tier,expected',[('Standard','FAIL'),('Advanced','PASS'),('Intelligent-Tiering','PASS'),
    (None,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_tier(tier,expected):
    assert next(f['verdict'] for f in check([EXP],tier) if f['rule_id']=='SSM_POLICY_ADVANCED_TIER')==expected


@pytest.mark.parametrize('policies',[[],[{}]])
def test_removal(policies):
    assert check(policies,'Standard')==[]


@pytest.mark.parametrize('raw',['[{"Type":"Expiration","Type":"Unknown"}]','bad','null','[NaN]',UNKNOWN])
def test_unresolved_json(raw):
    assert all(f['verdict']=='NEEDS_REVIEW' for f in check(raw,raw=True))


@pytest.mark.parametrize('name,expected',[('name','PASS'),('/'+'/'.join(['x']*15),'PASS'),
    ('/'+'/'.join(['x']*16),'FAIL'),('a//b','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),('/a/${name}','NEEDS_REVIEW')])
def test_name_hierarchy(name,expected):
    from aws_design_sheet.checks.registry import run_resource_checks
    resource=target('parameter','AWS::SSM::Parameter',Name=name)
    assert next(f['verdict'] for f in run_resource_checks(linked_design(resource),resource)
                if f['rule_id']=='SSM_PARAMETER_HIERARCHY_DEPTH')==expected
