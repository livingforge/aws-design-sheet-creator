"""Additional source failover conditions and declared NDI interface use."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved
from .output_context import flow

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={rule:[CF+'aws-resource-mediaconnect-flowsource.html',CF+'aws-properties-mediaconnect-flow-failoverconfig.html',CF+'aws-properties-mediaconnect-flow-sourcepriority.html',CF+'aws-resource-mediaconnect-flowvpcinterface.html'] for rule in ('MEDIACONNECT_ADDITIONAL_SOURCE_FAILOVER','MEDIACONNECT_DECLARED_SOURCE_COUNT','MEDIACONNECT_PRIMARY_SOURCE_IDENTITY','MEDIACONNECT_NDI_INLINE_INTERFACE')}
for urls in SOURCES.values():urls.append('https://docs.aws.amazon.com/mediaconnect/latest/ug/source-failover.html')
PROTOCOLS={'zixi-push','rtp-fec','rtp','rist','srt-listener','srt-caller'}


def additional(ctx,r):
    parent=flow(ctx,r)
    if parent is None:return 'NEEDS_REVIEW'
    state=value(ctx,parent,'/properties/SourceFailoverConfig/State')
    if state=='DISABLED':return 'FAIL'
    own=value(ctx,r,'/properties/Protocol');existing=value(ctx,parent,'/properties/Source/Protocol')
    pending=state!='ENABLED'
    if not literal(own) or own not in PROTOCOLS:pending=True
    elif literal(existing) and existing in PROTOCOLS|{'cdi','st2110-jpegxs','ndi-speed-hq','zixi-pull'}:
        if own!=existing:return 'FAIL'
    else:pending=True
    if own in ('srt-caller','srt-listener'):
        mode=value(ctx,parent,'/properties/SourceFailoverConfig/FailoverMode')
        if mode=='MERGE':return 'FAIL'
        if mode!='FAILOVER':pending=True
    return 'NEEDS_REVIEW' if pending else 'PASS'


def names(ctx,r):
    result=set()
    inline=value(ctx,r,'/properties/Source/Name')
    if literal(inline):result.add(inline)
    for source in ctx.design.resources:
        if source.type=='AWS::MediaConnect::FlowSource' and flow(ctx,source) is r:
            name=value(ctx,source,'/properties/Name')
            if literal(name):result.add(name)
    return result


def count(ctx,r,known):
    state=value(ctx,r,'/properties/SourceFailoverConfig/State')
    maximum=1 if state=='DISABLED' else 2 if state=='ENABLED' else None
    return 'FAIL' if maximum is not None and len(known)>maximum else 'NEEDS_REVIEW'


def primary(ctx,r,known):
    raw=value(ctx,r,'/properties/SourceFailoverConfig/SourcePriority/PrimarySource')
    if raw is ABSENT:return 'NOT_APPLICABLE'
    return 'PASS' if literal(raw) and raw in known else 'NEEDS_REVIEW'


def ndi_interface(ctx,r):
    parent=flow(ctx,r);name=value(ctx,r,'/properties/Name')
    if parent is None or not literal(name):return 'NEEDS_REVIEW'
    for output in ctx.design.resources:
        if output.type!='AWS::MediaConnect::FlowOutput' or flow(ctx,output) is not parent:continue
        if value(ctx,output,'/properties/Protocol')=='ndi-speed-hq' and value(ctx,output,'/properties/VpcInterfaceAttachment/VpcInterfaceName')==name:return 'FAIL'
    return 'NEEDS_REVIEW'


@resource_check(
    'AWS::MediaConnect::Flow',
    'AWS::MediaConnect::FlowSource',
    'AWS::MediaConnect::FlowVpcInterface',
)
def evaluate_mediaconnect_failover(design,resource):
    if resource.type not in ('AWS::MediaConnect::Flow','AWS::MediaConnect::FlowSource','AWS::MediaConnect::FlowVpcInterface'):return []
    ctx=_Context(design,resource)
    if resource.type.endswith('::FlowSource'):
        checks=[('MEDIACONNECT_ADDITIONAL_SOURCE_FAILOVER','/properties/FlowArn',additional(ctx,resource))]
    elif resource.type.endswith('::FlowVpcInterface'):
        checks=[('MEDIACONNECT_NDI_INLINE_INTERFACE','/properties/FlowArn',ndi_interface(ctx,resource))]
    else:
        known=names(ctx,resource) if resolved(resource) else set()
        checks=[('MEDIACONNECT_DECLARED_SOURCE_COUNT','/properties/SourceFailoverConfig/State',count(ctx,resource,known) if resolved(resource) else 'NEEDS_REVIEW'),('MEDIACONNECT_PRIMARY_SOURCE_IDENTITY','/properties/SourceFailoverConfig/SourcePriority/PrimarySource',primary(ctx,resource,known) if resolved(resource) else 'NEEDS_REVIEW')]
    out=[]
    for rule,path,verdict in checks:
        f=ctx.finding(rule,path,verdict,'Additional sources require enabled failover and the same known protocol; SRT requires FAILOVER mode. Count distinct declared source names against the failover maximum and recognize a declared primary source. An NDI output cannot use a standalone FlowVpcInterface. Unknown/external inventories and conditional flow references remain reviewable; no live source or traffic claim.')
        f['source_checked_at']='2026-10-04';out.append(f)
    return out
