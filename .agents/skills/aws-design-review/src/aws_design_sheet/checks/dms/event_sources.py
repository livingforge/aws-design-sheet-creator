"""DMS event source type checks using explicit references only."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved

SOURCES={'DMS_EVENT_SOURCE_TYPES':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dms-eventsubscription.html']}
KINDS={'replication-instance':'AWS::DMS::ReplicationInstance','replication-task':'AWS::DMS::ReplicationTask'}


@resource_check('AWS::DMS::EventSubscription')
def evaluate_dms_event_sources(design,resource):
    if resource.type!='AWS::DMS::EventSubscription':return []
    ctx=_Context(design,resource);path='/properties/SourceIds'
    ids=value(ctx,resource,path);source=value(ctx,resource,'/properties/SourceType');verdict='NEEDS_REVIEW'
    if ids is ABSENT:verdict='NOT_APPLICABLE'
    elif resolved(resource) and isinstance(ids,list) and 0<len(ids)<=1000:
        kinds=[];pending=False
        for i in range(len(ids)):
            candidates=[linked(ctx,resource,path+'/'+str(i),kind) for kind in KINDS.values()]
            known=[r for r in candidates if resolved(r)]
            if len(known)==1:kinds.append(known[0].type)
            else:pending=True
        expected=KINDS.get(source) if isinstance(source,str) else None
        if len(set(kinds))>1 or expected and any(k!=expected for k in kinds):verdict='FAIL'
        elif not pending and (source is ABSENT or expected):verdict='PASS'
    f=ctx.finding('DMS_EVENT_SOURCE_TYPES',path,verdict,
        'Explicit unique same-scope DMS source links must have one resource type and match a known SourceType. Arbitrary identifiers, unknown modes and ambiguous/external links remain reviewable; existence and event delivery are outside this check.')
    f['source_checked_at']='2026-10-04'
    return [f]
