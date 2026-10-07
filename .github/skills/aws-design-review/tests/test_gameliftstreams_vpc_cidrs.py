import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.gameliftstreams.vpc_cidrs import evaluate_gameliftstreams_vpc_cidrs
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(blocks=None):
    r=target('group','AWS::GameLiftStreams::StreamGroup',LocationConfigurations=[{'LocationName':'ap-northeast-1','VpcTransitConfiguration':{'Ipv4CidrBlocks':blocks if blocks is not None else ['10.0.1.0/24']}}])
    vpc=target('vpc','AWS::EC2::VPC',CidrBlock='10.0.0.0/16')
    d=linked_design(r,[vpc]);link(d,r,'LocationConfigurations/0/VpcTransitConfiguration/VpcId',vpc)
    return d,r,vpc


def verdicts(d,r):return [f['verdict'] for f in evaluate_gameliftstreams_vpc_cidrs(d,r)]


@pytest.mark.parametrize('blocks,expected',[
    (['10.0.1.0/24'],'PASS'),(['10.0.0.0/16'],'PASS'),
    (['10.0.255.255/32'],'PASS'),(['10.0.0.0/17','10.0.128.0/17'],'PASS'),
    (['10.0.0.0/15'],'NEEDS_REVIEW'),(['10.1.0.0/16'],'NEEDS_REVIEW'),
    (['10.0.1.1/24'],'NEEDS_REVIEW'),(['2001:db8::/64'],'NEEDS_REVIEW'),
    ([UNKNOWN],'NEEDS_REVIEW'),(['10.0.1.0/24',UNKNOWN],'NEEDS_REVIEW'),
    ([], 'NEEDS_REVIEW'),(['10.0.1.0/24']*6,'NEEDS_REVIEW')])
def test_positive_containment_and_unknown_ranges(blocks,expected):
    d,r,vpc=fixture(blocks)
    assert verdicts(d,r)==['PASS',expected]


def test_explicit_secondary_cidr():
    d,r,vpc=fixture(['10.1.1.0/24'])
    secondary=target('secondary','AWS::EC2::VPCCidrBlock',CidrBlock='10.1.0.0/16')
    d.resources.append(secondary);link(d,secondary,'VpcId',vpc)
    assert verdicts(d,r)==['PASS','PASS']
    d.relations[-1].condition='Maybe'
    assert verdicts(d,r)==['PASS','NEEDS_REVIEW']


@pytest.mark.parametrize('mode,expected',[
    ('account',['FAIL','NEEDS_REVIEW']),('location',['PASS','NEEDS_REVIEW']),
    ('other_region_location',['PASS','PASS']),('conditional',['NEEDS_REVIEW']*2),
    ('template',['NEEDS_REVIEW']*2),('raw_id',['NEEDS_REVIEW']*2),
    ('missing_link',['NEEDS_REVIEW']*2),('unknown_primary',['PASS','NEEDS_REVIEW']),
    ('unknown_parent',['NEEDS_REVIEW']*2)])
def test_reference_scope_and_evidence(mode,expected):
    d,r,vpc=fixture()
    if mode=='account':vpc.scope.account='222222222222'
    if mode=='location':vpc.scope.region='us-west-2'
    if mode=='other_region_location':
        vpc.scope.region='us-west-2';r.fields[0].candidates[0].value[0]['LocationName']='us-west-2'
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='template':vpc.template=TemplateContext(state='UNRESOLVED')
    if mode=='raw_id':r.fields[0].candidates[0].value[0]['VpcTransitConfiguration']['VpcId']='vpc-12345678'
    if mode=='missing_link':d.relations.clear()
    if mode=='unknown_primary':vpc.fields[0].candidates[0].value=UNKNOWN
    if mode=='unknown_parent':r.fields[0].candidates[0].value=UNKNOWN
    assert verdicts(d,r)==expected


def test_absent_transit_is_not_applicable():
    d,r,vpc=fixture();r.fields[0].candidates[0].value[0].pop('VpcTransitConfiguration');d.relations.clear()
    assert evaluate_gameliftstreams_vpc_cidrs(d,r)==[]


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='GAMELIFT_STREAMS_VPC_CIDR_SUBSET' and f['verdict']=='PASS' for f in results)
