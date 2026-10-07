import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN

BASE={'AppPorts':'8080','ProxyIngressPort':'15000','ProxyEgressPort':'15001','EgressIgnoredPorts':'','EgressIgnoredIPs':'','IgnoredUID':'1337'}


def check(options=None,*,user='1337',kind='APPMESH',extra=()):
    values=BASE if options is None else options
    items=[{'Name':k,'Value':v} for k,v in values.items()]+list(extra)
    resource=target('task','AWS::ECS::TaskDefinition',ContainerDefinitions=[{'Name':'proxy','User':user}],
        ProxyConfiguration={'Type':kind,'ContainerName':'proxy','ProxyConfigurationProperties':items})
    return {f['rule_id']:f['verdict'] for f in run_resource_checks(linked_design(resource),resource)}


@pytest.mark.parametrize('missing',list(BASE))
def test_required_keys(missing):
    assert check({k:v for k,v in BASE.items() if k!=missing})['ECS_PROXY_REQUIRED_PROPERTIES']=='FAIL'


def test_group_alternative_empty_exclusions():
    values={k:v for k,v in BASE.items() if k!='IgnoredUID'}
    values['IgnoredGID']='1337'
    assert check(values)['ECS_PROXY_REQUIRED_PROPERTIES']=='PASS'
    assert check()['ECS_PROXY_EGRESS_PORT_COUNT']=='PASS'


@pytest.mark.parametrize('extra',[[{'Name':UNKNOWN,'Value':'x'}],[{'Name':'AppPorts','Value':'80'}]])
def test_unknown_or_duplicate_key(extra):
    assert check(extra=extra)['ECS_PROXY_REQUIRED_PROPERTIES']=='NEEDS_REVIEW'


@pytest.mark.parametrize('user,expected',[('1337','PASS'),('01337','PASS'),('0','FAIL'),
    ('proxy','NEEDS_REVIEW'),('1337:1337','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_uid(user,expected):
    assert check(user=user)['ECS_PROXY_IGNORED_UID']==expected


@pytest.mark.parametrize('count,expected',[(0,'PASS'),(14,'PASS'),(15,'NEEDS_REVIEW'),(16,'FAIL')])
def test_egress_limit(count,expected):
    assert check({**BASE,'EgressIgnoredPorts':','.join(str(i+1) for i in range(count))})['ECS_PROXY_EGRESS_PORT_COUNT']==expected


@pytest.mark.parametrize('raw',[UNKNOWN,'22, 80','22-80','0','65536'])
def test_egress_unknown(raw):
    assert check({**BASE,'EgressIgnoredPorts':raw})['ECS_PROXY_EGRESS_PORT_COUNT']=='NEEDS_REVIEW'


def test_unknown_type_and_values():
    assert check(kind=UNKNOWN)['ECS_PROXY_REQUIRED_PROPERTIES']=='NEEDS_REVIEW'
    assert check({**BASE,'AppPorts':UNKNOWN})['ECS_PROXY_REQUIRED_PROPERTIES']=='NEEDS_REVIEW'


@pytest.mark.parametrize('essential,expected',[(True,'PASS'),(False,'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_proxy_essential(essential,expected):
    resource=target('task','AWS::ECS::TaskDefinition',ContainerDefinitions=[{'Name':'proxy','Essential':essential}],
        ProxyConfiguration={'Type':'APPMESH','ContainerName':'proxy'})
    results={f['rule_id']:f['verdict'] for f in run_resource_checks(linked_design(resource),resource)}
    assert results['ECS_PROXY_ESSENTIAL_CONTAINER']==expected


def test_fifteen_ports_with_implicit_ssh():
    assert check({**BASE,'EgressIgnoredPorts':','.join(str(i) for i in range(8,23))})['ECS_PROXY_EGRESS_PORT_COUNT']=='PASS'
