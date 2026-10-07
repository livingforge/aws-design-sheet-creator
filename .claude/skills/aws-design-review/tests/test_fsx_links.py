from pathlib import Path
import pytest
from aws_design_sheet.checks.fsx.capabilities_and_links import evaluate_fsx_capabilities_and_links
from aws_design_sheet.checks.emr.studio_vpc_links import evaluate_emr_studio_vpc_links
from aws_design_sheet.checks.registry import combine
fsx_links_checks = combine(evaluate_fsx_capabilities_and_links, evaluate_emr_studio_vpc_links)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('version,deployment,expected',[
    ('2.12','PERSISTENT_1','PASS'),('2.15','PERSISTENT_2','PASS'),('2.12.0','SCRATCH_2','PASS'),
    ('2.11','PERSISTENT_1','FAIL'),('2.9','PERSISTENT_1','FAIL'),('2.15','SCRATCH_1','FAIL'),
    (UNKNOWN,'PERSISTENT_2','NEEDS_REVIEW'),('2.15',UNKNOWN,'NEEDS_REVIEW'),('2.x','PERSISTENT_2','NEEDS_REVIEW'),
])
@pytest.mark.parametrize('mode',['linked','conditional','scope'])
def test_dra(version,deployment,expected,mode):
    r=target('main','AWS::FSx::DataRepositoryAssociation',FileSystemId='fs')
    fs=target('fs','AWS::FSx::FileSystem',FileSystemType='LUSTRE',FileSystemTypeVersion=version,LustreConfiguration={'DeploymentType':deployment})
    d=linked_design(r,[fs],[('FileSystemId','fs')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':fs.scope.account='222222222222'
    assert fsx_links_checks(d,r)[0]['verdict']==(expected if mode=='linked' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('service,resource',[('logs','log-group:/aws/fsx/test'),('firehose','deliverystream/aws-fsx-test')])
@pytest.mark.parametrize('mode',['same','account','region','unknown'])
def test_audit_scope(service,resource,mode):
    arn=UNKNOWN if mode=='unknown' else 'arn:aws:'+service+':'+('us-east-1' if mode=='region' else 'ap-northeast-1')+':'+('222222222222' if mode=='account' else '111111111111')+':'+resource
    r=target('main','AWS::FSx::FileSystem',WindowsConfiguration={'AuditLogConfiguration':{'AuditLogDestination':arn}})
    assert fsx_links_checks(linked_design(r),r)[0]['verdict']==('PASS' if mode=='same' else 'NEEDS_REVIEW' if mode=='unknown' else 'FAIL')


@pytest.mark.parametrize('name,expected',[('A','PASS'),('A'*15,'PASS'),('A'*16,'FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${Name}','NEEDS_REVIEW')])
def test_netbios(name,expected):
    r=target('main','AWS::FSx::StorageVirtualMachine',ActiveDirectoryConfiguration={'NetBiosName':name})
    assert fsx_links_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('field',['SubnetIds/0','EngineSecurityGroupId','WorkspaceSecurityGroupId'])
@pytest.mark.parametrize('mode',['same','different','literal','conditional','scope','unknown'])
def test_studio_vpc(field,mode):
    props={'SubnetIds':['member']} if field.startswith('SubnetIds') else {field:'member'}
    r=target('main','AWS::EMR::Studio',VpcId='vpc',**props)
    member=target('member','AWS::EC2::Subnet' if field.startswith('SubnetIds') else 'AWS::EC2::SecurityGroup',VpcId=UNKNOWN if mode=='unknown' else 'vpc')
    vpc=target('vpc','AWS::EC2::VPC');other=target('other','AWS::EC2::VPC')
    d=linked_design(r,[member,vpc,other],[('VpcId','vpc'),(field,'member')])
    if mode!='literal':
        from aws_design_sheet.models import Relation
        d.relations.append(Relation(id='member-vpc',source_resource_id='member',source_path='/properties/VpcId',target_resource_id='other' if mode=='different' else 'vpc',evidence_ids=[]))
    if mode=='conditional':d.relations[-1].condition='Maybe'
    if mode=='scope':member.scope.region='us-east-1'
    assert fsx_links_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='different' else 'NEEDS_REVIEW')


def test_checker_netbios():
    r=target('main','AWS::FSx::StorageVirtualMachine',ActiveDirectoryConfiguration={'NetBiosName':'A'*16})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='FSX_SVM_NETBIOS_LENGTH' and f['verdict']=='FAIL' for f in results)
