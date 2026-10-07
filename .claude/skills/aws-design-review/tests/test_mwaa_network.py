import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.mwaa.network import evaluate_mwaa_network
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(a=None,b=None,g=None):
    main=target('main','AWS::MWAA::Environment',NetworkConfiguration={'SubnetIds':['a','b'],'SecurityGroupIds':['g']})
    a=target('a','AWS::EC2::Subnet',**(a if a is not None else {'VpcId':'vpc-12345678','AvailabilityZone':'ap-northeast-1a'}))
    b=target('b','AWS::EC2::Subnet',**(b if b is not None else {'VpcId':'vpc-12345678','AvailabilityZone':'ap-northeast-1b'}))
    g=target('g','AWS::EC2::SecurityGroup',**(g if g is not None else {'VpcId':'vpc-12345678'}))
    d=linked_design(main,[a,b,g],[('NetworkConfiguration/SubnetIds/0','a'),('NetworkConfiguration/SubnetIds/1','b'),('NetworkConfiguration/SecurityGroupIds/0','g')])
    return d,main,a,b,g


def results(d,r):return {f['rule_id']:f['verdict'] for f in evaluate_mwaa_network(d,r)}


@pytest.mark.parametrize('a,b,expected',[
    ({'AvailabilityZone':'ap-northeast-1a'},{'AvailabilityZone':'ap-northeast-1b'},'PASS'),
    ({'AvailabilityZone':'ap-northeast-1a'},{'AvailabilityZone':'ap-northeast-1a'},'FAIL'),
    ({'AvailabilityZoneId':'apne1-az1'},{'AvailabilityZoneId':'apne1-az2'},'PASS'),
    ({'AvailabilityZoneId':'apne1-az1'},{'AvailabilityZoneId':'apne1-az1'},'FAIL'),
    ({'AvailabilityZone':'ap-northeast-1a'},{'AvailabilityZoneId':'apne1-az2'},'NEEDS_REVIEW'),
    ({'AvailabilityZone':UNKNOWN},{},'NEEDS_REVIEW'),
    ({'AvailabilityZone':'ap-northeast-1a','AvailabilityZoneId':'apne1-az1'},{'AvailabilityZone':'ap-northeast-1b','AvailabilityZoneId':'apne1-az1'},'NEEDS_REVIEW'),
])
def test_zones(a,b,expected):
    d,r,*_=fixture(a,b)
    assert results(d,r)['MWAA_SUBNET_AZ_DIVERSITY']==expected


@pytest.mark.parametrize('mode,expected',[('same','PASS'),('other_group','FAIL'),('other_subnet','FAIL'),('unknown','NEEDS_REVIEW'),('refs','PASS'),('different_refs','FAIL'),('mixed','NEEDS_REVIEW')])
def test_vpc_identity(mode,expected):
    d,r,a,b,g=fixture(g={'VpcId':'vpc-87654321'} if mode=='other_group' else None,b={'VpcId':'vpc-87654321'} if mode=='other_subnet' else None,a={'VpcId':UNKNOWN} if mode=='unknown' else None)
    if mode in ('refs','different_refs','mixed'):
        v=target('v','AWS::EC2::VPC');w=target('w','AWS::EC2::VPC');d.resources.extend([v,w])
        link(d,a,'VpcId',v)
        if mode!='mixed':link(d,b,'VpcId',v);link(d,g,'VpcId',w if mode=='different_refs' else v)
    assert results(d,r)['MWAA_NETWORK_VPC']==expected


@pytest.mark.parametrize('mode',['conditional','missing','scope','template','unknown_list','same_subnet'])
def test_incomplete_links(mode):
    d,r,a,b,g=fixture()
    expected='NEEDS_REVIEW'
    if mode=='conditional':d.relations[0].condition='Maybe'
    elif mode=='missing':d.relations.pop(0)
    elif mode=='scope':a.scope.region='us-east-1'
    elif mode=='template':a.template=TemplateContext(state='UNRESOLVED')
    elif mode=='unknown_list':r.fields[0].candidates[0].value=UNKNOWN
    else:d.relations[1].target_resource_id='a';expected='FAIL'
    assert results(d,r)['MWAA_SUBNET_AZ_DIVERSITY']==expected


@pytest.mark.parametrize('mode,expected',[(x,'FAIL' if x in ('igw','igw_ref','ipv6') else 'NEEDS_REVIEW') for x in ('igw','igw_ref','ipv6','nat','eigw','missing_association','conditional','duplicate_association','unknown_route','other_table','unknown_template','none')])
def test_private_route(mode,expected):
    d,r,a,b,g=fixture()
    table=target('table','AWS::EC2::RouteTable')
    assoc=target('assoc','AWS::EC2::SubnetRouteTableAssociation')
    props={'DestinationCidrBlock':'0.0.0.0/0','GatewayId':'igw-12345678'}
    if mode=='ipv6':props={'DestinationIpv6CidrBlock':'::/0','GatewayId':'igw-12345678'}
    if mode=='nat':props={'DestinationCidrBlock':'0.0.0.0/0','NatGatewayId':'nat-12345678'}
    if mode=='eigw':props={'DestinationIpv6CidrBlock':'::/0','EgressOnlyInternetGatewayId':'eigw-12345678'}
    if mode=='unknown_route':props={'DestinationCidrBlock':UNKNOWN,'GatewayId':'igw-12345678'}
    route=target('route','AWS::EC2::Route',**props)
    d.resources.extend([table,assoc,route]);link(d,assoc,'SubnetId',a);link(d,assoc,'RouteTableId',table);link(d,route,'RouteTableId',table)
    if mode=='igw_ref':
        gateway=target('igw','AWS::EC2::InternetGateway');d.resources.append(gateway);link(d,route,'GatewayId',gateway)
    if mode=='missing_association':d.resources.remove(assoc)
    if mode=='conditional':d.relations[-1].condition='Maybe'
    if mode=='duplicate_association':
        other=target('other','AWS::EC2::SubnetRouteTableAssociation');d.resources.append(other);link(d,other,'SubnetId',a);link(d,other,'RouteTableId',table)
    if mode=='other_table':d.relations[-1].target_resource_id='outside'
    if mode=='unknown_template':route.template=TemplateContext(state='UNRESOLVED')
    if mode=='none':d.resources.remove(route)
    assert results(d,r)['MWAA_PRIVATE_SUBNET_ROUTE']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='MWAA_NETWORK_VPC' and f['verdict']=='PASS' for f in rows)
