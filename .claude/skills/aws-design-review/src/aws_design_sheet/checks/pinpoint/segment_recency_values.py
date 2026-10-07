"""Checks for AWS::Pinpoint::Segment."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PINPOINT_SEGMENT_RECENCY_VALUES': [CF+'aws-properties-pinpoint-segment-recency.html'],
}


@resource_check('AWS::Pinpoint::Segment')
def evaluate_pinpoint_segment_recency_values(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Pinpoint::Segment':
        seen=set()
        for root in ('/properties/Dimensions/Behavior/Recency','/properties/SegmentGroups/Groups/*/Dimensions/*/Behavior/Recency'):
            for key,allowed in (('Duration',('HR_24','DAY_7','DAY_14','DAY_30')),('RecencyType',('ACTIVE','INACTIVE'))):
                for path in expand(ctx,resource,root+'/'+key):
                    if path in seen:continue
                    seen.add(path);raw=value(ctx,resource,path)
                    emit('PINPOINT_SEGMENT_RECENCY_VALUES',path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','explicit recency duration/type enum only; unknown fields/collections, other dimension enums, source segment provenance and actual membership remain held')
    return results
