"""Cognito log group account and declared KMS encryption evidence."""
import re
from ..common.context_values import linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved


def log_group(ctx, resource, path):
    if read(ctx,resource,path) is not ABSENT:return None
    refs=[r for r in ctx.design.relations if r.source_resource_id==resource.id and r.source_path==path]
    if len(refs)!=1 or refs[0].condition:return None
    group=ctx.by_id.get(refs[0].target_resource_id)
    if not resolved(group) or group.type!='AWS::Logs::LogGroup' or group.scope.environment!=resource.scope.environment:return None
    ctx.evidence.extend(refs[0].evidence_ids)
    ctx.dependencies.append(group.id+'/scope/account')
    return group


def log_verdict(ctx, resource, path):
    if not resolved(resource):return 'NEEDS_REVIEW'
    pool=linked(ctx,resource,'/properties/UserPoolId','AWS::Cognito::UserPool')
    if read(ctx,resource,'/properties/UserPoolId') is not ABSENT or not resolved(pool):pool=None
    group=log_group(ctx,resource,path)
    if group is not None:
        raw=read(ctx,group,'/properties/KmsKeyId')
        refs=[r for r in ctx.design.relations if r.source_resource_id==group.id and r.source_path=='/properties/KmsKeyId']
        encrypted=not refs and literal(raw) or raw is ABSENT and len(refs)==1 and not refs[0].condition
        if encrypted:return 'FAIL'
        if pool is not None and group.scope.account!=pool.scope.account:return 'FAIL'
        if pool is not None and raw is ABSENT and not refs:return 'PASS'
    arn=value(ctx,resource,path)
    match=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:logs:[a-z0-9-]+:([0-9]{12}):log-group:.+',arn) if literal(arn) else None
    if pool is not None and match is not None and match[1]!=pool.scope.account:return 'FAIL'
    return 'NEEDS_REVIEW'
