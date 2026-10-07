"""Mitigation destination groups must not share a static group hierarchy."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'IOT_MITIGATION_GROUP_HIERARCHY':[CF+'aws-properties-iot-mitigationaction-addthingstothinggroupparams.html',CF+'aws-resource-iot-thinggroup.html']}
PATH='/properties/ActionParams/AddThingsToThingGroupParams/ThingGroupNames'


def named(ctx,r,path):
    if not resolved(r):return None
    other=linked(ctx,r,path,'AWS::IoT::ThingGroup')
    if not resolved(other):return None
    raw=read(ctx,r,path);name=value(ctx,other,'/properties/ThingGroupName')
    return other if literal(raw) and literal(name) and raw==name else None


def ancestors(ctx,r):
    seen=set()
    for _ in range(32):
        if not resolved(r) or r.id in seen:return None,False
        if value(ctx,r,'/properties/QueryString') is not ABSENT:return None,False
        seen.add(r.id)
        if value(ctx,r,'/properties/ParentGroupName') is ABSENT:return seen,True
        parent=named(ctx,r,'/properties/ParentGroupName')
        if parent is None:return seen,False
        r=parent
    return None,False


@resource_check('AWS::IoT::MitigationAction')
def evaluate_iot_group_hierarchy(design,resource):
    if resource.type!='AWS::IoT::MitigationAction':return []
    ctx=_Context(design,resource);raw=value(ctx,resource,PATH)
    if raw is ABSENT:return []
    verdict='NEEDS_REVIEW'
    if resolved(resource) and isinstance(raw,list) and 0<len(raw)<=10:
        groups={};pending=False;conflict=False
        for i in range(len(raw)):
            group=named(ctx,resource,PATH+'/'+str(i))
            if group is None:pending=True;continue
            if group.id in groups:continue  # Repeated identity is not two different groups.
            chain,complete=ancestors(ctx,group)
            if chain is None:pending=True;continue
            if any(chain & other for other in groups.values()):conflict=True;break
            groups[group.id]=chain
            if not complete:pending=True
        if conflict:verdict='FAIL'
        elif groups and not pending:verdict='PASS'
    f=ctx.finding('IOT_MITIGATION_GROUP_HIERARCHY',PATH,verdict,'Explicit distinct destination groups cannot share an ancestor in a static IoT thing-group hierarchy. Follow named, same-scope, unconditional parent links with cycle/depth guards. A common known ancestor proves conflict even if a higher parent is external. PASS covers only the specified destination groups; existing thing memberships, dynamic groups and live execution state remain outside this check.')
    f['source_checked_at']='2026-10-04';return [f]
