from pathlib import Path
import pytest
from aws_design_sheet.checks.ivs.storage_bucket_region import evaluate_ivs_storage_bucket_region
from aws_design_sheet.checks.grafana.workspace_vpc_members import evaluate_grafana_workspace_vpc_members
from aws_design_sheet.checks.registry import combine
media_placement_checks = combine(evaluate_ivs_storage_bucket_region, evaluate_grafana_workspace_vpc_members)
from aws_design_sheet.models import Relation, TemplateContext
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('mode',['same','region','account','environment','name','unknown','ancestor','conditional','ambiguous','missing','wrong_type','template','bucket_template','scope'])
def test_bucket(mode):
    r=target('main','AWS::IVS::StorageConfiguration',S3=UNKNOWN if mode=='ancestor' else {'BucketName':UNKNOWN if mode=='unknown' else 'my-bucket'})
    b=target('bucket','AWS::S3::Bucket',BucketName='other-name' if mode=='name' else 'my-bucket')
    d=linked_design(r,[b],[] if mode=='missing' else [('S3/BucketName','bucket')])
    if mode in ('region','account','environment'):setattr(b.scope,mode,{'region':'us-east-1','account':'222222222222','environment':'other'}[mode])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='wrong_type':b.type='AWS::SNS::Topic'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='bucket_template':b.template=TemplateContext(state='UNRESOLVED')
    if mode=='scope':b.scope.account='unknown'
    assert media_placement_checks(d,r)[0]['verdict']==('PASS' if mode in ('same','account') else 'FAIL' if mode=='region' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['same','different','unknown_list','unknown_item','unknown_parent','empty','missing_member','missing_vpc','conditional_member','conditional_vpc','ambiguous','wrong_type','scope','template','member_template','vpc_template','conflict_and_unknown'])
def test_grafana(mode):
    config={'SubnetIds':['subnet'],'SecurityGroupIds':['sg']}
    if mode=='unknown_list':config['SubnetIds']=UNKNOWN
    if mode=='unknown_item':config['SubnetIds']=[UNKNOWN]
    if mode=='empty':config['SecurityGroupIds']=[]
    if mode=='unknown_parent':config=UNKNOWN
    if mode=='conflict_and_unknown':config['SubnetIds'].append(UNKNOWN)
    r=target('main','AWS::Grafana::Workspace',VpcConfiguration=config)
    subnet=target('subnet','AWS::EC2::Subnet',VpcId='vpc')
    sg=target('sg','AWS::EC2::SecurityGroup',VpcId='other' if mode in ('different','conflict_and_unknown') else 'vpc')
    vpc=target('vpc','AWS::EC2::VPC');other=target('other','AWS::EC2::VPC')
    d=linked_design(r,[subnet,sg,vpc,other],[('VpcConfiguration/SubnetIds/0','subnet'),('VpcConfiguration/SecurityGroupIds/0','sg')])
    for member,owner in [(subnet,'vpc'),(sg,'other' if mode in ('different','conflict_and_unknown') else 'vpc')]:
        d.relations.append(Relation(id=member.id+'-vpc',source_resource_id=member.id,source_path='/properties/VpcId',target_resource_id=owner,evidence_ids=[]))
    if mode=='missing_member':d.relations=d.relations[1:]
    if mode=='missing_vpc':d.relations=d.relations[:-1]
    if mode=='conditional_member':d.relations[0].condition='Maybe'
    if mode=='conditional_vpc':d.relations[-1].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='wrong_type':sg.type='AWS::SNS::Topic'
    if mode=='scope':subnet.scope.region='us-east-1'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='member_template':subnet.template=TemplateContext(state='UNRESOLVED')
    if mode=='vpc_template':vpc.template=TemplateContext(state='UNRESOLVED')
    assert media_placement_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode in ('different','conflict_and_unknown') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::Grafana::Workspace','AWS::IVS::StorageConfiguration'])
def test_omitted(kind):
    r=target('main',kind)
    assert not media_placement_checks(linked_design(r),r)


def test_checker_bucket():
    r=target('main','AWS::IVS::StorageConfiguration',S3={'BucketName':'my-bucket'})
    b=target('bucket','AWS::S3::Bucket',BucketName='my-bucket');b.scope.region='us-east-1'
    d=linked_design(r,[b],[('S3/BucketName','bucket')])
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='IVS_STORAGE_BUCKET_REGION' and f['verdict']=='FAIL' for f in results)
