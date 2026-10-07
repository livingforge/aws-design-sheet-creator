"""Pipes ECS override platform limits, keeping conflicting documentation open."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.scoped_resolution import resolved
from .task_context import ROOT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={r:[CF+'aws-properties-pipes-pipe-ecstaskoverride.html',CF+'aws-properties-pipes-pipe-ecsenvironmentfile.html',CF+'aws-properties-ecs-taskdefinition-runtimeplatform.html','https://docs.aws.amazon.com/AmazonECS/latest/developerguide/use-environment-file.html'] for r in ('PIPES_EPHEMERAL_PLATFORM','PIPES_ENV_FILES_PLATFORM')}
WINDOWS={'WINDOWS_SERVER_'+s for s in ('2019_FULL','2019_CORE','2016_FULL','2004_CORE','2022_CORE','2022_FULL','2025_CORE','2025_FULL','20H2_CORE')}


def launch(ctx,r):
    direct=value(ctx,r,ROOT+'/LaunchType');strategy=value(ctx,r,ROOT+'/CapacityProviderStrategy')
    if strategy is ABSENT:return direct if direct in ('FARGATE','EC2','EXTERNAL') else None
    if direct is not ABSENT or not isinstance(strategy,list) or not 1<=len(strategy)<=20:return None
    names=[value(ctx,r,ROOT+f'/CapacityProviderStrategy/{i}/CapacityProvider') for i in range(len(strategy))]
    return 'FARGATE' if all(n in ('FARGATE','FARGATE_SPOT') for n in names) else None


def environment_files(ctx,r):
    rows=value(ctx,r,ROOT+'/Overrides/ContainerOverrides')
    if rows is ABSENT:return False
    if not isinstance(rows,list) or len(rows)>100:return None
    pending=False
    for i in range(len(rows)):
        files=value(ctx,r,ROOT+f'/Overrides/ContainerOverrides/{i}/EnvironmentFiles')
        if files is ABSENT:continue
        if isinstance(files,list) and files:return True
        if files!=[]:pending=True
    return None if pending else False


def check(ctx,r,feature,present):
    if present is False:return 'NOT_APPLICABLE'
    if present is None or not resolved(r):return 'NEEDS_REVIEW'
    mode=launch(ctx,r)
    if mode in ('EC2','EXTERNAL'):return 'FAIL' if feature=='ephemeral' else 'NEEDS_REVIEW'
    if mode!='FARGATE':return 'NEEDS_REVIEW'
    if read(ctx,r,ROOT+'/TaskDefinitionArn') is not ABSENT:return 'NEEDS_REVIEW'
    task=linked(ctx,r,ROOT+'/TaskDefinitionArn','AWS::ECS::TaskDefinition')
    if not resolved(task):return 'NEEDS_REVIEW'
    os=value(ctx,task,'/properties/RuntimePlatform/OperatingSystemFamily')
    if os=='LINUX':minimum=(1,4,0)
    elif isinstance(os,str) and os in WINDOWS:
        if feature=='environment':return 'NEEDS_REVIEW'
        minimum=(1,0,0)
    else:return 'NEEDS_REVIEW'
    version=value(ctx,r,ROOT+'/PlatformVersion')
    if not isinstance(version,str) or not re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}',version):return 'NEEDS_REVIEW'
    return 'PASS' if tuple(map(int,version.split('.')))>=minimum else 'FAIL'


@resource_check('AWS::Pipes::Pipe')
def evaluate_pipes_platform(design,resource):
    if resource.type!='AWS::Pipes::Pipe':return []
    ctx=_Context(design,resource);raw=value(ctx,resource,ROOT+'/Overrides/EphemeralStorage')
    ephemeral=False if raw is ABSENT else True if isinstance(raw,dict) and '$state' not in raw else None
    out=[]
    for rule,feature,present in [('PIPES_EPHEMERAL_PLATFORM','ephemeral',ephemeral),('PIPES_ENV_FILES_PLATFORM','environment',environment_files(ctx,resource))]:
        f=ctx.finding(rule,ROOT+'/Overrides',check(ctx,resource,feature,present),'Explicit Fargate overrides require Linux platform >=1.4.0; ephemeral storage also supports Windows >=1.0.0. Windows environment files and non-Fargate environment-file applicability have conflicting CloudFormation/ECS documentation and remain reviewable. Require explicit linked task OS and numeric platform version; LATEST, defaults, custom capacity providers and dynamic input remain reviewable. PASS covers platform compatibility only, not file contents or runtime access.')
        f['source_checked_at']='2026-10-04';out.append(f)
    return out
