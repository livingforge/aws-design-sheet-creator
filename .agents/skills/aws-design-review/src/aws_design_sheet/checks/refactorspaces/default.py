"""Refactor Spaces active-route requirement within an explicit application."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

SOURCES={'REFACTOR_SPACES_ACTIVE_DEFAULT':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-refactorspaces-route.html']}


def identity(ctx,r,prop,kind,prefix):
    path='/properties/'+prop;raw=read(ctx,r,path)
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if refs:
        other=linked(ctx,r,path,kind)
        return ('resource',other.id) if resolved(other) and raw is ABSENT else None
    return ('literal',raw) if literal(raw) and re.fullmatch(prefix+r'-[0-9A-Za-z]{10}',raw) else None


def application(ctx,r):
    if not resolved(r):return None
    a=identity(ctx,r,'ApplicationIdentifier','AWS::RefactorSpaces::Application','app')
    e=identity(ctx,r,'EnvironmentIdentifier','AWS::RefactorSpaces::Environment','env')
    return (a,e) if a is not None and e is not None else None


def active_default(ctx,r):
    kind=value(ctx,r,'/properties/RouteType')
    if kind=='DEFAULT':return 'NOT_APPLICABLE'
    if kind!='URI_PATH':return 'NEEDS_REVIEW'
    state=value(ctx,r,'/properties/UriPathRoute/ActivationState')
    if state=='INACTIVE':return 'NOT_APPLICABLE'
    if state!='ACTIVE':return 'NEEDS_REVIEW'
    own=application(ctx,r)
    if own is None:return 'NEEDS_REVIEW'
    defaults=[];unknown=False
    for other in ctx.design.resources:
        if other.id==r.id or other.type!=r.type or other.scope!=r.scope:continue
        if application(ctx,other)!=own:continue
        other_kind=value(ctx,other,'/properties/RouteType')
        if other_kind=='DEFAULT':defaults.append(other)
        elif other_kind!='URI_PATH':unknown=True
    if len(defaults)!=1 or unknown:return 'NEEDS_REVIEW'
    state=value(ctx,defaults[0],'/properties/DefaultRoute/ActivationState')
    return 'PASS' if state=='ACTIVE' else 'FAIL' if state=='INACTIVE' else 'NEEDS_REVIEW'


@resource_check('AWS::RefactorSpaces::Route')
def evaluate_refactorspaces_default(design,resource):
    if resource.type!='AWS::RefactorSpaces::Route':return []
    ctx=_Context(design,resource)
    f=ctx.finding('REFACTOR_SPACES_ACTIVE_DEFAULT','/properties/UriPathRoute/ActivationState',active_default(ctx,resource),'An active URI_PATH route requires the same application/environment default route to be active. Compare explicit IDs or logical identities in one scope. Missing/ambiguous default routes and unspecified activation state remain reviewable because deployed inventory and update history are unknown. PASS only checks declared activation compatibility; first-route creation order remains a separate outstanding condition.')
    f['source_checked_at']='2026-10-04';return [f]
