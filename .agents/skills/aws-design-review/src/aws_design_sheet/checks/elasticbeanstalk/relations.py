"""Explicit application-version bucket and configuration-template relations."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved
from .inheritance import effective_stack

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'BEANSTALK_VERSION_BUCKET_REGION':[CF+'aws-resource-elasticbeanstalk-applicationversion.html',CF+'aws-resource-elasticbeanstalk-environment.html'],
 'BEANSTALK_SOURCE_SOLUTION_STACK':[CF+'aws-resource-elasticbeanstalk-configurationtemplate.html',CF+'aws-properties-elasticbeanstalk-configurationtemplate-sourceconfiguration.html',CF+'aws-resource-elasticbeanstalk-environment.html'],
 'BEANSTALK_IMAGE_SUPPORTED_ARCHITECTURE':[CF+'aws-properties-elasticbeanstalk-applicationversion-imagebuildconfiguration.html','https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html'],
}


def app(ctx,r,path):
    other=linked(ctx,r,path,'AWS::ElasticBeanstalk::Application')
    if resolved(other):return ('resource',other.id)
    raw=value(ctx,r,path)
    return ('literal',raw) if literal(raw) else None


def same_app(ctx,a,apath,b,bpath):
    x=app(ctx,a,apath);y=app(ctx,b,bpath)
    return bool(x and y and x==y)


def bucket_region(ctx,r):
    path='/properties/SourceBundle/S3Bucket'
    other=linked(ctx,r,path,'AWS::S3::Bucket')
    if resolved(other):return other.scope.region
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if len(refs)!=1 or refs[0].condition:return None
    other=ctx.by_id.get(refs[0].target_resource_id);raw=read(ctx,r,path)
    if not resolved(other) or other.type!='AWS::S3::Bucket' or other.scope.environment!=r.scope.environment:return None
    if not literal(raw) or not re.fullmatch(r'[a-z0-9.-]{3,63}',raw) or value(ctx,other,'/properties/BucketName')!=raw:return None
    ctx.evidence.extend(refs[0].evidence_ids)
    return other.scope.region


def version_verdict(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    region=bucket_region(ctx,r)
    if region is None:return 'NEEDS_REVIEW'
    found=False;pending=False
    for env in ctx.design.resources:
        if env.type!='AWS::ElasticBeanstalk::Environment':continue
        refs=[ref for ref in ctx.design.relations if ref.source_resource_id==env.id and ref.source_path=='/properties/VersionLabel' and ref.target_resource_id==r.id]
        if not refs:continue
        if not resolved(env) or linked(ctx,env,'/properties/VersionLabel',r.type) is not r or not same_app(ctx,env,'/properties/ApplicationName',r,'/properties/ApplicationName'):
            pending=True;continue
        found=True
        if env.scope.region!=region:return 'FAIL'
    return 'PASS' if found and not pending else 'NEEDS_REVIEW'


def template_verdict(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    own=value(ctx,r,'/properties/SolutionStackName');source=value(ctx,r,'/properties/SourceConfiguration')
    if own is ABSENT or source is ABSENT:return 'NOT_APPLICABLE'
    if not literal(own):return 'NEEDS_REVIEW'
    other=linked(ctx,r,'/properties/SourceConfiguration/TemplateName',r.type)
    if not resolved(other) or not same_app(ctx,r,'/properties/SourceConfiguration/ApplicationName',other,'/properties/ApplicationName'):return 'NEEDS_REVIEW'
    stack=effective_stack(ctx,other,same_app)
    if not literal(stack):return 'NEEDS_REVIEW'
    return 'PASS' if stack==own else 'FAIL'


def supported_architectures(ctx,env):
    rows=value(ctx,env,'/properties/OptionSettings')
    if not isinstance(rows,list):return None
    matches=[]
    for i in range(len(rows)):
        base='/properties/OptionSettings/'+str(i)
        namespace=value(ctx,env,base+'/Namespace');name=value(ctx,env,base+'/OptionName')
        if not literal(namespace) or not literal(name):return None
        if namespace=='aws:ec2:instances' and name=='SupportedArchitectures':matches.append(base)
    if len(matches)!=1:return None
    raw=value(ctx,env,matches[0]+'/Value')
    if not literal(raw):return None
    items={x.strip() for x in raw.split(',')}
    return items if items and items<={'x86_64','arm64','i386'} else None


def architecture_verdict(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    build=value(ctx,r,'/properties/ImageConfiguration/Build')
    if build is ABSENT:return 'NOT_APPLICABLE'
    if not isinstance(build,dict) or '$state' in build:return 'NEEDS_REVIEW'
    raw=value(ctx,r,'/properties/ImageConfiguration/Build/Architecture')
    if raw is ABSENT:raw='amd64'
    if not isinstance(raw,str) or raw not in ('amd64','arm64'):return 'NEEDS_REVIEW'
    expected='x86_64' if raw=='amd64' else 'arm64'
    found=False;pending=False
    for env in ctx.design.resources:
        if env.type!='AWS::ElasticBeanstalk::Environment':continue
        refs=[ref for ref in ctx.design.relations if ref.source_resource_id==env.id and ref.source_path=='/properties/VersionLabel' and ref.target_resource_id==r.id]
        if not refs:continue
        if not resolved(env) or linked(ctx,env,'/properties/VersionLabel',r.type) is not r or not same_app(ctx,env,'/properties/ApplicationName',r,'/properties/ApplicationName'):
            pending=True;continue
        supported=supported_architectures(ctx,env)
        if supported is None:pending=True;continue
        if expected not in supported:return 'FAIL'
        found=True
        if len(supported)!=1:pending=True
    return 'PASS' if found and not pending else 'NEEDS_REVIEW'


@resource_check('AWS::ElasticBeanstalk::ApplicationVersion','AWS::ElasticBeanstalk::ConfigurationTemplate')
def evaluate_elasticbeanstalk_relations(design,resource):
    ctx=_Context(design,resource)
    if resource.type=='AWS::ElasticBeanstalk::ApplicationVersion':
        rule='BEANSTALK_VERSION_BUCKET_REGION';path='/properties/SourceBundle/S3Bucket';verdict=version_verdict(ctx,resource)
        reason='Compare the explicitly linked source bucket Region with known environments referring to this version and application. PASS covers those linked consumers only; absent, conditional or external consumers are not certified.'
    elif resource.type=='AWS::ElasticBeanstalk::ConfigurationTemplate':
        rule='BEANSTALK_SOURCE_SOLUTION_STACK';path='/properties/SourceConfiguration';verdict=template_verdict(ctx,resource)
        reason='When both properties are supplied, compare SolutionStackName with the explicitly linked source template in the identified application. Follow explicit template and environment inheritance with cycle and depth guards; external and unresolved effective source stacks remain reviewable.'
    else:return []
    f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results=[f]
    if resource.type=='AWS::ElasticBeanstalk::ApplicationVersion':
        f=ctx.finding('BEANSTALK_IMAGE_SUPPORTED_ARCHITECTURE','/properties/ImageConfiguration/Build/Architecture',architecture_verdict(ctx,resource),'Compare image build architecture (documented amd64 default) with an explicit singleton SupportedArchitectures environment option. An excluded architecture fails; multiple allowed architectures cannot establish the actual instance architecture. InstanceTypes, inherited options and external consumers remain unverified.')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
