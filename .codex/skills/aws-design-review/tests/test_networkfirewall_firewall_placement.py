import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.networkfirewall.firewall_placement import evaluate_networkfirewall_firewall_placement
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture():
    r=target('fw','AWS::NetworkFirewall::Firewall',VpcId='vpc-12345678',SubnetMappings=[{},{}])
    ss=[target(n,'AWS::EC2::Subnet',VpcId='vpc-12345678',AvailabilityZone='ap-northeast-1'+z) for n,z in [('a','a'),('b','b')]]
    d=linked_design(r,ss)
    for i,s in enumerate(ss):link(d,r,f'SubnetMappings/{i}/SubnetId',s)
    return d,r,ss


def verdicts(d,r):return [f['verdict'] for f in evaluate_networkfirewall_firewall_placement(d,r)]


def test_subnets_same_vpc_distinct_az():
    d,r,*_=fixture();assert verdicts(d,r)==['PASS','PASS','NOT_APPLICABLE']


@pytest.mark.parametrize('mode,want',[
    ('vpc',['FAIL','PASS']),('zone',['PASS','FAIL']),('missing',['NEEDS_REVIEW']*2),
    ('conditional',['NEEDS_REVIEW']*2),('scope',['NEEDS_REVIEW']*2),('template',['NEEDS_REVIEW']*2),
    ('unknown_zone',['PASS','NEEDS_REVIEW']),('unknown_vpc',['NEEDS_REVIEW','PASS']),
    ('same_subnet',['PASS','FAIL']),('duplicate',['NEEDS_REVIEW']*2),
    ('unknown_list',['NEEDS_REVIEW']*2)])
def test_subnet_evidence(mode,want):
    d,r,ss=fixture()
    if mode=='vpc':ss[1].fields[0].candidates[0].value='vpc-87654321'
    if mode=='zone':ss[1].fields[1].candidates[0].value='ap-northeast-1a'
    if mode=='missing':d.resources.remove(ss[1])
    if mode=='conditional':d.relations[1].condition='Maybe'
    if mode=='scope':ss[1].scope.region='us-east-1'
    if mode=='template':ss[1].template=TemplateContext(state='UNRESOLVED')
    if mode=='unknown_zone':ss[1].fields[1].candidates[0].value=UNKNOWN
    if mode=='unknown_vpc':ss[1].fields[0].candidates[0].value=UNKNOWN
    if mode=='same_subnet':d.relations[1].target_resource_id=ss[0].id
    if mode=='duplicate':link(d,r,'SubnetMappings/1/SubnetId',ss[1])
    if mode=='unknown_list':r.fields[1].candidates[0].value=UNKNOWN
    assert verdicts(d,r)[:2]==want


@pytest.mark.parametrize('az,want',[('ap-northeast-1a','PASS'),('us-east-1a','FAIL'),('apne1-az1','NEEDS_REVIEW'),('us-west-2-lax-1a','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_transit_region(az,want):
    r=target('fw','AWS::NetworkFirewall::Firewall',AvailabilityZoneMappings=[{'AvailabilityZone':az}])
    t=target('tgw','AWS::EC2::TransitGateway');d=linked_design(r,[t]);link(d,r,'TransitGatewayId',t)
    assert verdicts(d,r)==['NOT_APPLICABLE','NOT_APPLICABLE',want]


@pytest.mark.parametrize('mode',['literal','conditional','missing','template'])
def test_transit_reference_uncertainty(mode):
    r=target('fw','AWS::NetworkFirewall::Firewall',AvailabilityZoneMappings=[{'AvailabilityZone':'ap-northeast-1a'}])
    t=target('tgw','AWS::EC2::TransitGateway');d=linked_design(r,[t]);link(d,r,'TransitGatewayId',t)
    if mode=='literal':r.fields+=target('dummy',r.type,TransitGatewayId='tgw-12345678').fields
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='missing':d.resources.remove(t)
    if mode=='template':t.template=TemplateContext(state='UNRESOLVED')
    assert verdicts(d,r)[2]=='NEEDS_REVIEW'


def test_all_subnet_pairs_checked():
    d,r,ss=fixture()
    third=target('c','AWS::EC2::Subnet',VpcId='vpc-12345678',AvailabilityZone='ap-northeast-1b')
    d.resources.append(third);r.fields[1].candidates[0].value.append({});link(d,r,'SubnetMappings/2/SubnetId',third)
    assert verdicts(d,r)[:2]==['PASS','FAIL']


def test_all_transit_zones_checked():
    r=target('fw','AWS::NetworkFirewall::Firewall',AvailabilityZoneMappings=[{'AvailabilityZone':'ap-northeast-1a'},{'AvailabilityZone':'us-east-1a'}])
    t=target('tgw','AWS::EC2::TransitGateway');d=linked_design(r,[t]);link(d,r,'TransitGatewayId',t)
    assert verdicts(d,r)[2]=='FAIL'


def test_conflicting_az_evidence_is_held():
    d,r,ss=fixture()
    for s in ss:s.fields+=target('dummy',s.type,AvailabilityZoneId='apne1-az1').fields
    assert verdicts(d,r)[:2]==['PASS','NEEDS_REVIEW']


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='NETWORK_FIREWALL_SUBNET_VPC' and f['verdict']=='PASS' for f in results)
