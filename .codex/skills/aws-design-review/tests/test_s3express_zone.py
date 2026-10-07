import pytest
from aws_design_sheet.checks.s3express.zone import evaluate_s3express_zone
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(zone='apne1-az1',name=None):
    r=target('ap','AWS::S3Express::AccessPoint',Name=name or 'access--'+zone+'--xa-s3')
    b=target('bucket','AWS::S3Express::DirectoryBucket',LocationName=zone)
    d=linked_design(r,[b]);link(d,r,'Bucket',b)
    return d,r,b


def verdict(d,r):return evaluate_s3express_zone(d,r)[0]['verdict']


@pytest.mark.parametrize('zone,name,want',[
    ('apne1-az1','access--apne1-az1--xa-s3','PASS'),
    ('apne1-az1','access--apne1-az2--xa-s3','FAIL'),
    ('usw2-lax1-az1','access--usw2-lax1-az1--xa-s3','PASS'),
    ('usw2-lax1-az1','access--usw2-lax1-az2--xa-s3','FAIL'),
    ('apne1-az1','access--ap-northeast-1a--xa-s3','NEEDS_REVIEW'),
    ('apne1-az1','access--apne1-az1--x-s3','NEEDS_REVIEW')])
def test_zone_matching(zone,name,want):
    d,r,*_=fixture(zone,name);assert verdict(d,r)==want


@pytest.mark.parametrize('mode',['conditional','missing','duplicate','scope','unknown_location','unknown_name','wrong_literal','wrong_owner','conflicting_bucket_name'])
def test_uncertainty(mode):
    d,r,b=fixture()
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='missing':d.resources.remove(b)
    if mode=='duplicate':link(d,r,'Bucket',b)
    if mode=='scope':b.scope.region='us-east-1'
    if mode=='unknown_location':b.fields[0].candidates[0].value=UNKNOWN
    if mode=='unknown_name':r.fields[0].candidates[0].value=UNKNOWN
    if mode=='wrong_literal':r.fields+=target('dummy',r.type,Bucket='other--apne1-az1--x-s3').fields
    if mode=='wrong_owner':r.fields+=target('dummy',r.type,BucketAccountId='222222222222').fields
    if mode=='conflicting_bucket_name':b.fields+=target('dummy',b.type,BucketName='bucket--apne1-az2--x-s3').fields
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_matching_bucket_literal_and_owner():
    d,r,b=fixture();name='bucket--apne1-az1--x-s3'
    b.fields+=target('dummy',b.type,BucketName=name).fields
    r.fields+=target('dummy',r.type,Bucket=name,BucketAccountId='111111111111').fields
    assert verdict(d,r)=='PASS'


def test_generated_access_point_name():
    d,r,b=fixture();r.fields=[]
    assert verdict(d,r)=='NOT_APPLICABLE'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="S3EXPRESS_ACCESS_POINT_BUCKET_ZONE" and f["verdict"]=="PASS" for f in results)
