"""MediaPackage multiview source-group and CMAF requirements."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'MEDIAPACKAGE_MULTIVIEW_SOURCES':[CF+'aws-properties-mediapackagev2-channel-multiviewconfiguration.html',CF+'aws-resource-mediapackagev2-channel.html']}


def group(ctx,r):
    path='/properties/ChannelGroupName'
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if refs:
        target=linked(ctx,r,path,'AWS::MediaPackageV2::ChannelGroup')
        if not resolved(target):return None
        raw=read(ctx,r,path)
        if raw is ABSENT:return ('logical',target.id)
        name=value(ctx,target,path)
        return ('name',name) if literal(raw) and raw==name else None
    name=value(ctx,r,path)
    return ('name',name) if literal(name) else None


def sources(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    raw=value(ctx,r,'/properties/MultiviewConfiguration/AvailableSources')
    if raw is ABSENT:return 'NOT_APPLICABLE'
    if value(ctx,r,'/properties/InputType')!='MULTIVIEW':return 'NEEDS_REVIEW'
    if not isinstance(raw,list) or not 1<=len(raw)<=10:return 'NEEDS_REVIEW'
    own=group(ctx,r);pending=False
    for i in range(len(raw)):
        path=f'/properties/MultiviewConfiguration/AvailableSources/{i}'
        other=linked(ctx,r,path,r.type)
        if not resolved(other):pending=True;continue
        name=read(ctx,r,path)
        if name is not ABSENT and (not literal(name) or name!=value(ctx,other,'/properties/ChannelName')):pending=True;continue
        peer=group(ctx,other)
        if own is not None and peer is not None and own[0]==peer[0] and own!=peer:return 'FAIL'
        if own is None or peer is None or own[0]!=peer[0]:pending=True
        typ=value(ctx,other,'/properties/InputType')
        if typ in ('HLS','MULTIVIEW'):return 'FAIL'
        if typ!='CMAF':pending=True
    return 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::MediaPackageV2::Channel')
def evaluate_mediapackagev2_multiview_sources(design,resource):
    if resource.type!='AWS::MediaPackageV2::Channel':return []
    ctx=_Context(design,resource)
    f=ctx.finding('MEDIAPACKAGE_MULTIVIEW_SOURCES','/properties/MultiviewConfiguration/AvailableSources',sources(ctx,resource),'Each declared multiview source channel must use CMAF input and belong to the same channel group. Explicit source references must agree with supplied source names. Missing external sources, unresolved types, conditional links and incomparable logical/literal group identities remain reviewable. PASS concerns declared group and input format only, not media availability.')
    f['source_checked_at']='2026-10-04';return [f]
