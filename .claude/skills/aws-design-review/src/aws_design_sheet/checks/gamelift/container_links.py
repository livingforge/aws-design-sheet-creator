"""Container fleet group type and operating-system port relations."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
API='https://docs.aws.amazon.com/gameliftservers/latest/apireference/'
SOURCES={rule:[CF+'aws-resource-gamelift-containerfleet.html',CF+'aws-resource-gamelift-containergroupdefinition.html',CF+'aws-properties-gamelift-containerfleet-ippermission.html',API+'API_CreateContainerFleet.html',API+'API_CreateContainerGroupDefinition.html'] for rule in ('GAMELIFT_CONTAINER_GROUP_TYPES','GAMELIFT_CONTAINER_OS_PORTS')}
GROUPS=(('GameServerContainerGroupDefinitionName','GAME_SERVER'),('PerInstanceContainerGroupDefinitionName','PER_INSTANCE'))


def definition(ctx,r,key):
    if not resolved(r):return None
    path='/properties/'+key;other=linked(ctx,r,path,'AWS::GameLift::ContainerGroupDefinition')
    if not resolved(other):return None
    raw=read(ctx,r,path);name=value(ctx,other,'/properties/Name')
    if not literal(raw) or not literal(name):return None
    if raw.startswith('arn:'):
        m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:gamelift:([a-z0-9-]+):([0-9]{12}):containergroupdefinition/([a-zA-Z0-9-]+)(?::([0-9]{1,10}))?',raw)
        if not m or (m[1],m[2],m[3])!=(other.scope.region,other.scope.account,name):return None
        if m[4] is not None:
            version=value(ctx,other,'/properties/VersionNumber')
            if type(version) is not int or version!=int(m[4]):return None
    elif raw!=name:return None
    return other


def group_types(ctx,r,groups):
    if not resolved(r):return 'NEEDS_REVIEW'
    absent=[value(ctx,r,'/properties/'+key) is ABSENT for key,_ in GROUPS]
    if all(absent):return 'PASS'  # API explicitly allows an empty CREATED fleet.
    pending=absent[0]  # A per-instance-only fleet is not one of the documented scenarios.
    for i,(_,expected) in enumerate(GROUPS):
        if absent[i]:continue
        other=groups[i]
        if other is None:pending=True;continue
        kind=value(ctx,other,'/properties/ContainerGroupType')
        if kind is ABSENT:kind='GAME_SERVER'
        if kind not in ('GAME_SERVER','PER_INSTANCE'):pending=True
        elif kind!=expected:return 'FAIL'
    return 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::GameLift::ContainerFleet')
def evaluate_gamelift_container_links(design,resource):
    if resource.type!='AWS::GameLift::ContainerFleet':return []
    ctx=_Context(design,resource);groups=[definition(ctx,resource,key) for key,_ in GROUPS]
    reason='Match explicit group names/ARNs and version evidence to GAME_SERVER or PER_INSTANCE roles, including the documented GAME_SERVER default. API allows a fleet without groups in CREATED state; that does not mean it can host games. Conditional, external, version-mismatched and unknown-template evidence remains reviewable.'
    results=[ctx.finding('GAMELIFT_CONTAINER_GROUP_TYPES','/properties/GameServerContainerGroupDefinitionName',group_types(ctx,resource,groups),reason)]
    os=value(ctx,groups[0],'/properties/OperatingSystem') if groups[0] else None
    # CF requires an explicit OS, even though the API prose also mentions a default.
    for path in expand(ctx,resource,'/properties/InstanceInboundPermissions/*'):
        verdict='NEEDS_REVIEW'
        if path.count('/')==3 and groups[0] is not None and os=='AMAZON_LINUX_2023':
            a=value(ctx,resource,path+'/FromPort');b=value(ctx,resource,path+'/ToPort')
            if type(a) is int and type(b) is int:verdict='PASS' if (a==b==22 or 1026<=a<=b<=60000) else 'FAIL'
        results.append(ctx.finding('GAMELIFT_CONTAINER_OS_PORTS',path,verdict,'For an explicitly linked AMAZON_LINUX_2023 game-server group, the entire inbound port interval must be port 22 alone or within 1026–60000. The container group schema currently supports only that OS; unrecognized platforms are held, not mapped from arbitrary text. Version and scope uncertainty remain reviewable. Reserved internal ports and connection-port matching are separate checks.'))
    for f in results:f['source_checked_at']='2026-10-04'
    return results
