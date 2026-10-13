"""Checks for AWS::FSx::DataRepositoryAssociation."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'FSX_DRA_LOCAL_PATHS': [CF+'aws-resource-fsx-datarepositoryassociation.html'],
}


def canonical_path(raw):
    if not literal(raw) or len(raw)>4096 or not raw.startswith('/'):
        return None
    if raw=='/':return ()
    parts=raw[1:].removesuffix('/').split('/')
    if any(p in ('.','..') or not re.fullmatch(r'[A-Za-z0-9_.-]+',p) for p in parts):
        return None
    return tuple(parts)


def dra_paths(ctx,resource):
    if resource.template is not None and resource.template.state.value!='KNOWN':
        return 'NEEDS_REVIEW'
    fs=linked(ctx,resource,'/properties/FileSystemId','AWS::FSx::FileSystem')
    own=canonical_path(value(ctx,resource,'/properties/FileSystemPath'))
    if fs is None or own is None or len(ctx.design.resources)>10000:
        return 'NEEDS_REVIEW'
    paths=set()
    for other in ctx.design.resources:
        if other.type!=resource.type or other.scope!=resource.scope:
            continue
        if other.template is not None and other.template.state.value!='KNOWN':
            continue
        owner=linked(ctx,other,'/properties/FileSystemId','AWS::FSx::FileSystem')
        path=canonical_path(value(ctx,other,'/properties/FileSystemPath'))
        if owner is not None and owner.id==fs.id and path is not None:
            paths.add(path)
    # Equal paths may be aliases for the same declared association: do not
    # double-count them or claim two distinct associations solely from IDs.
    if len(paths)>8 or any(p!=own and (p[:len(own)]==own or own[:len(p)]==p) for p in paths):
        return 'FAIL'
    return 'NEEDS_REVIEW'


@resource_check('AWS::FSx::DataRepositoryAssociation')
def evaluate_fsx_dra_local_paths(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::FSx::DataRepositoryAssociation':
        emit('FSX_DRA_LOCAL_PATHS','/properties/FileSystemPath',dra_paths(ctx,resource),'distinct canonical paths on a uniquely linked filesystem prove ancestor overlap or more than eight associations; aliases, unsupported path syntax, external associations and first-association ordering remain held; absence of conflict is not a completeness PASS')
    return results
