"""Checks for these resource types:

- AWS::AppStream::AppBlock
- AWS::AppStream::Application
- AWS::AppStream::StackFleetAssociation
- AWS::AppStream::StackUserAssociation
"""
from ...template_dependencies import members, ordering
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPSTREAM_APPLICATION_ELASTIC_FLEET': [CF+'aws-resource-appstream-application.html',CF+'aws-resource-appstream-applicationfleetassociation.html'],
    'APPSTREAM_APPBLOCK_ELASTIC_FLEET': [CF+'aws-resource-appstream-appblock.html',CF+'aws-resource-appstream-applicationfleetassociation.html'],
    'APPSTREAM_USERPOOL_DOMAIN_FLEET': [CF+'aws-resource-appstream-stackuserassociation.html',CF+'aws-resource-appstream-stackfleetassociation.html'],
    'APPSTREAM_STACK_FLEET_ORDER': [CF+'aws-resource-appstream-stackfleetassociation.html',CF+'aws-attribute-dependson.html'],
}


def association_target(ctx, resource, key, kind):
    """Use a unique reference without contradicting an explicit source value."""
    path='/properties/'+key
    target=linked(ctx,resource,path,kind)
    if not resolved(target):return None
    raw=read(ctx,resource,path)
    if raw is ABSENT:return target
    if key in ('FleetName','StackName') and literal(raw) and raw==value(ctx,target,'/properties/Name'):
        return target
    # Literal/generated ARNs need independently comparable physical identity.
    return None


def application_fleets(ctx,r,block=False):
    if not resolved(r):return 'NEEDS_REVIEW'
    observed=False;pending=False
    for association in ctx.design.resources:
        if association.type!='AWS::AppStream::ApplicationFleetAssociation' or association.scope!=r.scope:continue
        if not resolved(association):pending=True;continue
        app=association_target(ctx,association,'ApplicationArn','AWS::AppStream::Application')
        if not resolved(app):pending=True;continue
        owner=association_target(ctx,app,'AppBlockArn','AWS::AppStream::AppBlock') if block else app
        if not resolved(owner):pending=True;continue
        if owner.id!=r.id:continue
        observed=True
        fleet=association_target(ctx,association,'FleetName','AWS::AppStream::Fleet')
        kind=value(ctx,fleet,'/properties/FleetType') if resolved(fleet) else None
        if kind in ('ALWAYS_ON','ON_DEMAND'):return 'FAIL'
        if kind!='ELASTIC':pending=True
    return 'PASS' if observed and not pending else 'NEEDS_REVIEW'


def userpool_fleets(ctx,r):
    if not resolved(r) or value(ctx,r,'/properties/AuthenticationType')!='USERPOOL':return 'NEEDS_REVIEW'
    stack=association_target(ctx,r,'StackName','AWS::AppStream::Stack')
    if not resolved(stack):return 'NEEDS_REVIEW'
    observed=False;pending=False
    for association in ctx.design.resources:
        if association.type!='AWS::AppStream::StackFleetAssociation' or association.scope!=r.scope:continue
        if not resolved(association):pending=True;continue
        owner=association_target(ctx,association,'StackName','AWS::AppStream::Stack')
        if not resolved(owner):pending=True;continue
        if owner.id!=stack.id:continue
        observed=True
        fleet=association_target(ctx,association,'FleetName','AWS::AppStream::Fleet')
        if not resolved(fleet):pending=True;continue
        domain=value(ctx,fleet,'/properties/DomainJoinInfo/DirectoryName')
        if literal(domain):return 'FAIL'
        if value(ctx,fleet,'/properties/DomainJoinInfo') is not ABSENT:pending=True
    return 'PASS' if observed and not pending else 'NEEDS_REVIEW'


@resource_check(
    'AWS::AppStream::Application',
    'AWS::AppStream::AppBlock',
    'AWS::AppStream::StackUserAssociation',
    'AWS::AppStream::StackFleetAssociation',
)
def evaluate_appstream_associations(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type in ('AWS::AppStream::Application','AWS::AppStream::AppBlock'):
        block=resource.type.endswith('::AppBlock')
        emit('APPSTREAM_APPBLOCK_ELASTIC_FLEET' if block else 'APPSTREAM_APPLICATION_ELASTIC_FLEET','/properties/AppBlockArn' if not block else '/properties/Name',application_fleets(ctx,resource,block),'only uniquely linked same-scope application/fleet associations in supplied design are checked; explicit ALWAYS_ON/ON_DEMAND is incompatible; missing consumers, unknown/conditional/external fleets and unmodeled associations remain held')
    if resource.type=='AWS::AppStream::StackUserAssociation':
        emit('APPSTREAM_USERPOOL_DOMAIN_FLEET','/properties/StackName',userpool_fleets(ctx,resource),'explicit USERPOOL stack cannot have a uniquely linked fleet with literal DirectoryName; only supplied association witnesses checked, missing or unknown fleets and live joins remain held')
    if resource.type=='AWS::AppStream::StackFleetAssociation':
        pool=members(design,resource);targets=[]
        for key,kind in [('FleetName','AWS::AppStream::Fleet'),('StackName','AWS::AppStream::Stack')]:
            target=linked(ctx,resource,'/properties/'+key,kind)
            if target is not None:
                raw=read(ctx,resource,'/properties/'+key)
                if raw is not ABSENT and (not literal(raw) or raw!=value(ctx,target,'/properties/Name')):target=None
            if target is None:
                name=value(ctx,resource,'/properties/'+key)
                matches=[r for r in pool if r.type==kind and literal(name) and value(ctx,r,'/properties/Name')==name]
                target=matches[0] if len(matches)==1 else None
            if resolved(target) and target in pool:targets.append(target)
        if len(targets)==2 and resolved(resource):
            try: finding=ordering(ctx,'APPSTREAM_STACK_FLEET_ORDER',targets)
            except RecursionError: finding=ctx.finding('APPSTREAM_STACK_FLEET_ORDER','/template/depends_on','NEEDS_REVIEW','Dependency graph exceeds bounded recursion; review required.')
            finding['source_checked_at']='2026-10-04';results.append(finding)
        else:emit('APPSTREAM_STACK_FLEET_ORDER','/template/depends_on','NEEDS_REVIEW','both targets require unique explicit membership in the same template; external resources and incomplete template context remain held')
    return results
