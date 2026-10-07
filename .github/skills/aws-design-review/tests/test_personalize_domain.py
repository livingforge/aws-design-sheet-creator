import pytest
from aws_design_sheet.checks.personalize.domain import evaluate_personalize_domain
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(own='ECOMMERCE',group='ECOMMERCE'):
    r=target('schema','AWS::Personalize::Schema',**({} if own is None else {'Domain':own}))
    g=target('group','AWS::Personalize::DatasetGroup',**({} if group is None else {'Domain':group}))
    ds=target('dataset','AWS::Personalize::Dataset')
    d=linked_design(r,[g,ds]);link(d,ds,'SchemaArn',r);link(d,ds,'DatasetGroupArn',g)
    return d,r,g,ds


def verdict(d,r):return evaluate_personalize_domain(d,r)[0]['verdict']


@pytest.mark.parametrize('own,group,want',[
    ('ECOMMERCE','ECOMMERCE','PASS'),('VIDEO_ON_DEMAND','VIDEO_ON_DEMAND','PASS'),
    ('ECOMMERCE','VIDEO_ON_DEMAND','FAIL'),(None,'ECOMMERCE','FAIL'),
    (UNKNOWN,'ECOMMERCE','NEEDS_REVIEW'),('ECOMMERCE',UNKNOWN,'NEEDS_REVIEW'),
    (None,None,'NOT_APPLICABLE'),('ECOMMERCE',None,'NOT_APPLICABLE')])
def test_domain_conditions(own,group,want):
    d,r,*_=fixture(own,group);assert verdict(d,r)==want


@pytest.mark.parametrize('mode',['no_consumer','conditional','duplicate','scope','literal_schema','literal_group','missing_group'])
def test_reference_uncertainty(mode):
    d,r,g,ds=fixture()
    if mode=='no_consumer':d.resources.remove(ds)
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='duplicate':link(d,ds,'SchemaArn',r)
    if mode=='scope':g.scope.region='us-east-1'
    if mode=='literal_schema':ds.fields+=target('dummy',ds.type,SchemaArn='arn:aws:personalize:ap-northeast-1:111111111111:schema/schema').fields
    if mode=='literal_group':ds.fields+=target('dummy',ds.type,DatasetGroupArn='arn:aws:personalize:ap-northeast-1:111111111111:dataset-group/group').fields
    if mode=='missing_group':d.resources.remove(g)
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_every_consumer_checked():
    d,r,g,ds=fixture();second=target('second','AWS::Personalize::Dataset');other=target('other','AWS::Personalize::DatasetGroup',Domain='VIDEO_ON_DEMAND')
    d.resources.extend([second,other]);link(d,second,'SchemaArn',r);link(d,second,'DatasetGroupArn',other)
    assert verdict(d,r)=='FAIL'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="PERSONALIZE_SCHEMA_GROUP_DOMAIN" and f["verdict"]=="PASS" for f in results)
