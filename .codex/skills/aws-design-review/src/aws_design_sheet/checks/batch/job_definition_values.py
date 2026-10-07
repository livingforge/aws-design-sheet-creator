"""Batch EFS dependencies and bounded literal retry patterns."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
    'BATCH_EFS_IAM_ROLE':[CF+'aws-properties-batch-jobdefinition-efsauthorizationconfig.html',CF+'aws-properties-batch-jobdefinition-ecstaskproperties.html',CF+'aws-properties-batch-jobdefinition-multinodeecstaskproperties.html'],
    'BATCH_NESTED_EFS_DEPENDENCIES':[CF+'aws-properties-batch-jobdefinition-efsauthorizationconfig.html'],
    'BATCH_RETRY_GLOB':[CF+'aws-properties-batch-jobdefinition-evaluateonexit.html'],
}


@resource_check('AWS::Batch::JobDefinition')
def evaluate_batch_job_definition_values(design,resource):
    if resource.type!='AWS::Batch::JobDefinition':return []
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    for pattern,rolekey in [('/properties/ContainerProperties','JobRoleArn'),
                           ('/properties/NodeProperties/NodeRangeProperties/*/Container','JobRoleArn'),
                           ('/properties/EcsProperties/TaskProperties/*','TaskRoleArn'),
                           ('/properties/NodeProperties/NodeRangeProperties/*/EcsProperties/TaskProperties/*','TaskRoleArn')]:
        for container in expand(ctx,resource,pattern):
            for path in expand(ctx,resource,container+'/Volumes/*/EfsVolumeConfiguration'):
                iam=value(ctx,resource,path+'/AuthorizationConfig/Iam')
                if iam not in (ABSENT,'DISABLED'):
                    role=value(ctx,resource,container+'/'+rolekey)
                    verdict='NEEDS_REVIEW' if iam!='ENABLED' or role is UNKNOWN else 'FAIL' if role is ABSENT else 'PASS' if literal(role) else 'NEEDS_REVIEW'
                    emit('BATCH_EFS_IAM_ROLE',path+'/AuthorizationConfig/Iam',verdict,'EFS IAM authorization requires an explicit job/task role; unresolved roles and effective IAM policy are separate')
                if container=='/properties/ContainerProperties':continue
                access=value(ctx,resource,path+'/AuthorizationConfig/AccessPointId')
                if iam in (ABSENT,'DISABLED') and access is ABSENT:continue
                pending=iam not in (ABSENT,'DISABLED','ENABLED') or access is not ABSENT and not literal(access)
                fail=False
                if iam=='ENABLED' or literal(access):
                    transit=value(ctx,resource,path+'/TransitEncryption')
                    if transit is ABSENT or transit=='DISABLED':fail=True
                    elif transit!='ENABLED':pending=True
                if literal(access):
                    root=value(ctx,resource,path+'/RootDirectory')
                    if root is not ABSENT and root!='/':
                        if literal(root):fail=True
                        else:pending=True
                emit('BATCH_NESTED_EFS_DEPENDENCIES',path,'FAIL' if fail else 'NEEDS_REVIEW' if pending else 'PASS',
                     'nested EFS IAM/access-point mounts require transit encryption; access-point root must be omitted or /; unresolved values remain under review')
    for path in expand(ctx,resource,'/properties/RetryStrategy/EvaluateOnExit/*'):
        for key in ('OnExitCode','OnReason','OnStatusReason'):
            raw=value(ctx,resource,path+'/'+key)
            if raw is ABSENT:continue
            verdict='NEEDS_REVIEW'
            if isinstance(raw,str) and raw.isascii() and raw and '${' not in raw and '{{' not in raw:
                syntax=r'[0-9]+\*?' if key=='OnExitCode' else r'[A-Za-z0-9.:\s]+\*?'
                if raw!='*':verdict='PASS' if len(raw)<=512 and re.fullmatch(syntax,raw) else 'FAIL'
            emit('BATCH_RETRY_GLOB',path+'/'+key,verdict,'checks up-to-512 ASCII glob characters with an optional trailing asterisk; empty/pure-wildcard, Unicode and unresolved patterns remain under review')
    return results
