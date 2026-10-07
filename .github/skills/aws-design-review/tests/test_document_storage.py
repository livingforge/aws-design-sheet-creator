from pathlib import Path
import pytest
from aws_design_sheet.checks.docdb.cluster_and_subnet_group import evaluate_docdb_cluster_and_subnet_group
from aws_design_sheet.checks.docdbelastic.cluster_values import evaluate_docdbelastic_cluster_values
from aws_design_sheet.checks.efs.filesystem_modes import evaluate_efs_filesystem_modes
from aws_design_sheet.checks.config.bucket_object_lock import evaluate_config_bucket_object_lock
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
document_storage_checks = combine(evaluate_docdb_cluster_and_subnet_group, evaluate_docdbelastic_cluster_values, evaluate_efs_filesystem_modes, evaluate_config_bucket_object_lock)


@pytest.mark.parametrize('kind,field,allowed',[
    ('DocDB::DBCluster','NetworkType',['IPV4','DUAL']),
    ('DocDB::DBCluster','StorageType',['standard','iopt1']),
    ('DocDBElastic::Cluster','AuthType',['PLAIN_TEXT','SECRET_ARN']),
    ('EFS::FileSystem','PerformanceMode',['generalPurpose','maxIO']),
    ('EFS::FileSystem','ThroughputMode',['bursting','provisioned','elastic']),
])
@pytest.mark.parametrize('case',['valid','invalid','unknown','dynamic','empty','absent'])
def test_modes(kind,field,allowed,case):
    for valid in allowed:
        raw={'valid':valid,'invalid':'INVALID','unknown':UNKNOWN,'dynamic':{'Ref':'Input'},'empty':''}.get(case)
        r=target('main','AWS::'+kind,**({} if case=='absent' else {field:raw}))
        result=document_storage_checks(linked_design(r),r)
        if case=='absent':assert result==[]
        else:assert result[0]['verdict']==('PASS' if case=='valid' else 'FAIL' if case=='invalid' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('capacity,expected',[(2,'PASS'),(4,'PASS'),(8,'PASS'),(16,'PASS'),(32,'PASS'),(64,'PASS'),(1,'FAIL'),(3,'FAIL'),(65,'FAIL'),(True,'NEEDS_REVIEW'),(2.0,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_capacity(capacity,expected):
    r=target('main','AWS::DocDBElastic::Cluster',ShardCapacity=capacity)
    assert document_storage_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('count,expected',[(1,'PASS'),(32,'PASS'),(33,'FAIL'),(False,'NEEDS_REVIEW'),('32','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_count(count,expected):
    r=target('main','AWS::DocDBElastic::Cluster',ShardCount=count)
    assert document_storage_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['different','same','literal','conditional','scope','unknown','azid','single','empty','unresolved','duplicate','three','partly_unknown','oversized'])
def test_subnet_spread(mode):
    ids=[] if mode=='empty' else ['a'] if mode=='single' else UNKNOWN if mode=='unresolved' else ['a','b','c'] if mode in ('three','partly_unknown') else ['a']*21 if mode=='oversized' else ['a','b']
    r=target('main','AWS::DocDB::DBSubnetGroup',SubnetIds=ids)
    a=target('a','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a')
    b=target('b','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a' if mode=='same' else UNKNOWN if mode=='unknown' else 'apne1-az2' if mode=='azid' else 'ap-northeast-1c')
    c=target('c','AWS::EC2::Subnet',AvailabilityZone=UNKNOWN if mode=='partly_unknown' else 'ap-northeast-1d')
    links=[] if mode=='literal' else [('SubnetIds/0','a'),('SubnetIds/1','b'),('SubnetIds/2','c')]
    if mode=='duplicate':links.append(('SubnetIds/1','a'))
    d=linked_design(r,[a,b,c],links)
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':b.scope.account='222222222222'
    expected='PASS' if mode in ('different','three') else 'FAIL' if mode in ('same','single','empty') else 'NEEDS_REVIEW'
    assert document_storage_checks(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('flag,expected',[(True,'NEEDS_REVIEW'),(False,'PASS'),(None,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),('true','NEEDS_REVIEW')])
@pytest.mark.parametrize('mode',['linked','literal','conditional','scope'])
def test_bucket_lock(flag,expected,mode):
    r=target('main','AWS::Config::DeliveryChannel',S3BucketName='bucket')
    b=target('bucket','AWS::S3::Bucket',BucketName='bucket',**({} if flag is None else {'ObjectLockEnabled':flag}))
    d=linked_design(r,[b],[] if mode=='literal' else [('S3BucketName','bucket')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':b.scope.region='us-east-1'
    assert document_storage_checks(d,r)[0]['verdict']==(expected if mode=='linked' else 'NEEDS_REVIEW')


def test_checker_bucket_lock():
    r=target('main','AWS::Config::DeliveryChannel',S3BucketName='bucket')
    b=target('bucket','AWS::S3::Bucket',BucketName='bucket',ObjectLockEnabled=True,ObjectLockConfiguration={'Rule':{'DefaultRetention':{'Mode':'GOVERNANCE','Days':1}}})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r,[b],[('S3BucketName','bucket')]))['results']
    assert any(f['rule_id']=='CONFIG_BUCKET_OBJECT_LOCK' and f['verdict']=='FAIL' for f in results)
