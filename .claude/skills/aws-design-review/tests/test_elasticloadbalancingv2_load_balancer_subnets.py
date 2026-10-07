import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(zones,kind='application',mapping=False,outpost=False):
    name='SubnetMappings' if mapping else 'Subnets'
    entries=[{'SubnetId':{'Ref':str(i)}} if mapping else {'Ref':str(i)} for i in range(len(zones))]
    main=target('lb','AWS::ElasticLoadBalancingV2::LoadBalancer',**{name:entries},**({'Type':kind} if kind is not None else {}))
    subnets=[target(str(i),'AWS::EC2::Subnet',AvailabilityZone=zone,**({'OutpostArn':'arn:aws:outposts:ap-northeast-1:123456789012:outpost/op-123'} if outpost else {})) for i,zone in enumerate(zones)]
    data=linked_design(main,subnets,[(name+f'/{i}'+('/SubnetId' if mapping else ''),str(i)) for i in range(len(zones))])
    return {r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}


@pytest.mark.parametrize('mapping',[False,True])
@pytest.mark.parametrize('zones,expected',[
    (['ap-northeast-1a'],'FAIL'), (['ap-northeast-1a','ap-northeast-1c'],'PASS'),
    ([UNKNOWN],'NEEDS_REVIEW'), (['ap-northeast-1-local-1a'],'NEEDS_REVIEW'),
])
def test_regional_count_and_unknown_placement(mapping,zones,expected):
    assert check(zones,mapping=mapping)['ELBV2_ALB_SUBNET_COUNT']==expected


def test_zone_duplicates_and_other_types():
    assert check(['ap-northeast-1a','ap-northeast-1a'])['ELBV2_SUBNET_ZONES']=='FAIL'
    assert check(['ap-northeast-1a'],'network')['ELBV2_SUBNET_ZONES']=='PASS'
    assert 'ELBV2_ALB_SUBNET_COUNT' not in check(['ap-northeast-1a'],'gateway')
    assert check(['ap-northeast-1a'],None)['ELBV2_ALB_SUBNET_COUNT']=='FAIL'


def test_outpost_count():
    assert check(['ap-northeast-1a'],outpost=True)['ELBV2_ALB_SUBNET_COUNT']=='PASS'
    assert check(['ap-northeast-1a','ap-northeast-1c'],outpost=True)['ELBV2_ALB_SUBNET_COUNT']=='FAIL'


def test_unknown_and_ambiguous_sources():
    for props in [{'Subnets':UNKNOWN},{'Subnets':[],'SubnetMappings':[]}]:
        main=target('lb','AWS::ElasticLoadBalancingV2::LoadBalancer',**props)
        findings={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
        assert findings['ELBV2_SUBNET_ZONES']=='NEEDS_REVIEW'
