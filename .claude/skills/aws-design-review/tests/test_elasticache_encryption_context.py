import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.elasticache.encryption_context import evaluate_elasticache_encryption_context
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(engine='redis',version='6.2',**props):
    r=target('main','AWS::ElastiCache::ReplicationGroup',Engine=engine,EngineVersion=version,CacheSubnetGroupName='group',**props)
    g=target('group','AWS::ElastiCache::SubnetGroup',CacheSubnetGroupName='group',SubnetIds=['subnet'])
    s=target('subnet','AWS::EC2::Subnet',VpcId='vpc-12345678')
    d=linked_design(r,[g,s],[('CacheSubnetGroupName','group')]);link(d,g,'SubnetIds/0',s)
    return d,r,g,s


@pytest.mark.parametrize('engine,version,at_rest,expected',[
    ('redis','3.1.0',True,'FAIL'),('redis','3.2.6',True,'NEEDS_REVIEW'),('redis','4.0.9',True,'NEEDS_REVIEW'),
    ('redis','4.0.10',True,'PASS'),('redis','4.0',True,'NEEDS_REVIEW'),('redis','4.1',True,'PASS'),
    ('redis','7.1',True,'PASS'),('redis','3.2.5',False,'FAIL'),('redis','3.2.6',False,'PASS'),
    ('redis','3.2',False,'NEEDS_REVIEW'),('redis','4.0',False,'PASS'),
    ('valkey','7.1',True,'FAIL'),('valkey','7.2',True,'PASS'),('valkey','8.0',False,'PASS'),
    ('Valkey','7.2',True,'NEEDS_REVIEW'),('redis',UNKNOWN,True,'NEEDS_REVIEW'),('redis','6.x',False,'NEEDS_REVIEW')])
def test_version(engine,version,at_rest,expected):
    prop='AtRestEncryptionEnabled' if at_rest else 'TransitEncryptionEnabled'
    d,r,*_=fixture(engine,version,**{prop:True})
    assert next(f for f in evaluate_elasticache_encryption_context(d,r) if f['rule_id']=='CACHE_ENCRYPTION_ENGINE_VERSION' and f['path']=='/properties/'+prop)['verdict']==expected


@pytest.mark.parametrize('mode,expected',[(x,'PASS' if x in ('known','vpc_ref','uppercase_group') else 'NEEDS_REVIEW') for x in ('known','vpc_ref','uppercase_group','wrong_name','external','conditional','scope','template','missing_vpc','unknown_subnets')])
def test_vpc_evidence(mode,expected):
    d,r,g,s=fixture(TransitEncryptionEnabled=True)
    if mode=='vpc_ref':v=target('v','AWS::EC2::VPC');d.resources.append(v);link(d,s,'VpcId',v)
    if mode=='uppercase_group':g.fields[0].candidates[0].value='GROUP'
    if mode=='wrong_name':g.fields[0].candidates[0].value='other'
    if mode=='external':d.relations=[]
    if mode=='conditional':d.relations[1].condition='Maybe'
    if mode=='scope':s.scope.region='us-east-1'
    if mode=='template':g.template=TemplateContext(state='UNRESOLVED')
    if mode=='missing_vpc':s.fields=[]
    if mode=='unknown_subnets':g.fields[1].candidates[0].value=UNKNOWN
    actual=evaluate_elasticache_encryption_context(d,r)
    assert next(f for f in actual if f['rule_id']=='CACHE_ENCRYPTION_VPC_CONDITION')['verdict']==expected


def test_false_unknown_and_ambiguous_default():
    d,r,*_=fixture(AtRestEncryptionEnabled=False)
    assert all(f['verdict']=='NOT_APPLICABLE' for f in evaluate_elasticache_encryption_context(d,r))
    d,r,*_=fixture(AtRestEncryptionEnabled=UNKNOWN)
    assert all(f['verdict']=='NEEDS_REVIEW' for f in evaluate_elasticache_encryption_context(d,r))
    d,r,*_=fixture('valkey','7.2')
    assert all(f['verdict']=='NEEDS_REVIEW' for f in evaluate_elasticache_encryption_context(d,r))


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture(TransitEncryptionEnabled=True);root=Path(__file__).resolve().parents[1]
    actual=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='CACHE_ENCRYPTION_VPC_CONDITION' and f['verdict']=='PASS' for f in actual)
