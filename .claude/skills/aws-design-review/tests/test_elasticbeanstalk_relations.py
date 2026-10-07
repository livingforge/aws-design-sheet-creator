import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.elasticbeanstalk.relations import evaluate_elasticbeanstalk_relations
from test_autoscaling_group_and_scaling_policy import target,linked_design
from test_template_dependencies import link


@pytest.mark.parametrize('region,expected',[('ap-northeast-1','PASS'),('us-east-1','FAIL')])
@pytest.mark.parametrize('mode',['known','conditional','source_template','bucket_template','env_template','no_consumer','app_mismatch','bucket_name_mismatch'])
def test_version(region,expected,mode):
    r=target('main','AWS::ElasticBeanstalk::ApplicationVersion',ApplicationName='app',SourceBundle={'S3Bucket':'source-bucket'})
    bucket=target('bucket','AWS::S3::Bucket',BucketName='source-bucket');bucket.scope.region=region
    env=target('env','AWS::ElasticBeanstalk::Environment',ApplicationName='other' if mode=='app_mismatch' else 'app',VersionLabel='main')
    d=linked_design(r,[bucket,env],[('SourceBundle/S3Bucket','bucket')])
    if mode!='no_consumer':link(d,env,'VersionLabel',r,'maybe' if mode=='conditional' else None)
    if mode=='source_template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='bucket_template':bucket.template=TemplateContext(state='UNRESOLVED')
    if mode=='env_template':env.template=TemplateContext(state='UNRESOLVED')
    if mode=='bucket_name_mismatch':bucket.fields[0].candidates[0].value='other-bucket'
    # A same-scope explicit reference establishes identity even without a matching display literal.
    held=mode not in ('known','bucket_name_mismatch') or (mode=='bucket_name_mismatch' and region!='ap-northeast-1')
    assert evaluate_elasticbeanstalk_relations(d,r)[0]['verdict']==('NEEDS_REVIEW' if held else expected)


@pytest.mark.parametrize('stack,expected',[('stack-v1','PASS'),('stack-v2','FAIL'),({'$state':'UNRESOLVED'},'NEEDS_REVIEW')])
@pytest.mark.parametrize('mode',['known','conditional','template','region','app_mismatch'])
def test_source_stack(stack,expected,mode):
    r=target('main','AWS::ElasticBeanstalk::ConfigurationTemplate',ApplicationName='new-app',SolutionStackName='stack-v1',SourceConfiguration={'ApplicationName':'source-app','TemplateName':'source'})
    other=target('source',r.type,ApplicationName='other' if mode=='app_mismatch' else 'source-app',SolutionStackName=stack)
    d=linked_design(r,[other],[('SourceConfiguration/TemplateName','source')])
    if mode=='conditional':d.relations[0].condition='maybe'
    if mode=='template':other.template=TemplateContext(state='UNRESOLVED')
    if mode=='region':other.scope.region='us-east-1'
    assert evaluate_elasticbeanstalk_relations(d,r)[0]['verdict']==(expected if mode=='known' else 'NEEDS_REVIEW')


def test_source_inherited_stack():
    r=target('main','AWS::ElasticBeanstalk::ConfigurationTemplate',SolutionStackName='stack',SourceConfiguration={'ApplicationName':'app','TemplateName':'source'})
    other=target('source',r.type,ApplicationName='app',EnvironmentId='e-123')
    assert evaluate_elasticbeanstalk_relations(linked_design(r,[other],[('SourceConfiguration/TemplateName','source')]),r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('props',[{}, {'SolutionStackName':'stack'},{'SourceConfiguration':{'TemplateName':'source'}}])
def test_optional_condition(props):
    r=target('main','AWS::ElasticBeanstalk::ConfigurationTemplate',**props)
    assert evaluate_elasticbeanstalk_relations(linked_design(r),r)[0]['verdict']=='NOT_APPLICABLE'


def test_linked_application_identity():
    r=target('main','AWS::ElasticBeanstalk::ConfigurationTemplate',SolutionStackName='stack',SourceConfiguration={'ApplicationName':'app','TemplateName':'source'})
    other=target('source',r.type,ApplicationName='app',SolutionStackName='stack')
    application=target('app','AWS::ElasticBeanstalk::Application')
    d=linked_design(r,[other,application],[('SourceConfiguration/TemplateName','source'),('SourceConfiguration/ApplicationName','app')])
    link(d,other,'ApplicationName',application)
    assert evaluate_elasticbeanstalk_relations(d,r)[0]['verdict']=='PASS'


def test_known_bad_consumer_survives_unknown_consumer():
    r=target('main','AWS::ElasticBeanstalk::ApplicationVersion',ApplicationName='app',SourceBundle={'S3Bucket':'source-bucket'})
    bucket=target('bucket','AWS::S3::Bucket',BucketName='source-bucket');bucket.scope.region='us-east-1'
    env=target('env','AWS::ElasticBeanstalk::Environment',ApplicationName='app',VersionLabel='main')
    unknown=target('unknown',env.type,ApplicationName='app',VersionLabel='main');unknown.template=TemplateContext(state='UNRESOLVED')
    d=linked_design(r,[bucket,unknown,env],[('SourceBundle/S3Bucket','bucket')])
    link(d,unknown,'VersionLabel',r);link(d,env,'VersionLabel',r)
    assert evaluate_elasticbeanstalk_relations(d,r)[0]['verdict']=='FAIL'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::ElasticBeanstalk::ConfigurationTemplate',SolutionStackName='stack1',SourceConfiguration={'ApplicationName':'app','TemplateName':'source'})
    other=target('source',r.type,ApplicationName='app',SolutionStackName='stack2')
    d=linked_design(r,[other],[('SourceConfiguration/TemplateName','source')])
    assert any(f['rule_id']=='BEANSTALK_SOURCE_SOLUTION_STACK' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'])


@pytest.mark.parametrize('arch,allowed,expected',[
    ('amd64','x86_64','PASS'),('amd64','arm64','FAIL'),('arm64','arm64','PASS'),
    ('arm64','x86_64','FAIL'),('amd64','x86_64,arm64','NEEDS_REVIEW'),
    ('arm64','x86_64,i386','FAIL'),('amd64','future','NEEDS_REVIEW'),
    (None,'x86_64','PASS'),(None,'arm64','FAIL'),
    ({'$state':'UNRESOLVED'},'arm64','NEEDS_REVIEW'),
])
@pytest.mark.parametrize('mode',['known','conditional','duplicate','unknown_option'])
def test_image_architecture(arch,allowed,expected,mode):
    build={} if arch is None else {'Architecture':arch}
    r=target('main','AWS::ElasticBeanstalk::ApplicationVersion',ApplicationName='app',ImageConfiguration={'Build':build})
    row={'Namespace':'aws:ec2:instances','OptionName':'SupportedArchitectures','Value':allowed}
    rows=[row,row] if mode=='duplicate' else [row,{'$state':'UNRESOLVED'}] if mode=='unknown_option' else [row]
    env=target('env','AWS::ElasticBeanstalk::Environment',ApplicationName='app',VersionLabel='main',OptionSettings=rows)
    d=linked_design(r,[env],[]);link(d,env,'VersionLabel',r,'maybe' if mode=='conditional' else None)
    f=next(f for f in evaluate_elasticbeanstalk_relations(d,r) if f['rule_id']=='BEANSTALK_IMAGE_SUPPORTED_ARCHITECTURE')
    assert f['verdict']==(expected if mode=='known' else 'NEEDS_REVIEW')
