"""MediaConnect output conditions using explicit flow and source declarations."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={rule:[CF+'aws-properties-mediaconnect-flowoutput-mediastreamoutputconfiguration.html',CF+'aws-properties-mediaconnect-flow-ndiconfig.html',CF+'aws-properties-mediaconnect-flow-mediastream.html'] for rule in ('MEDIACONNECT_OUTPUT_NDI_ENABLED','MEDIACONNECT_OUTPUT_ENCODING_MEDIA_TYPE','MEDIACONNECT_OUTPUT_CDI_ENCODING_CONTEXT')}
SOURCES['MEDIACONNECT_OUTPUT_CDI_ENCODING_CONTEXT'].extend([CF+'aws-resource-mediaconnect-flowsource.html','https://docs.aws.amazon.com/mediaconnect/latest/ug/source-failover.html'])


def flow(ctx,r):
    if not resolved(r) or read(ctx,r,'/properties/FlowArn') is not ABSENT:return None
    target=linked(ctx,r,'/properties/FlowArn','AWS::MediaConnect::Flow')
    return target if resolved(target) else None


def ndi(ctx,r,parent):
    protocol=value(ctx,r,'/properties/Protocol')
    if not resolved(r):return 'NEEDS_REVIEW'
    if protocol in ('zixi-push','rtp-fec','rtp','zixi-pull','rist','srt-listener','srt-caller','st2110-jpegxs','cdi'):return 'NOT_APPLICABLE'
    if protocol!='ndi-speed-hq' or parent is None:return 'NEEDS_REVIEW'
    state=value(ctx,parent,'/properties/NdiConfig/NdiState')
    return 'PASS' if state=='ENABLED' else 'FAIL' if state is ABSENT or state=='DISABLED' else 'NEEDS_REVIEW'


def encoding(ctx,r,parent,path):
    if parent is None:return 'NEEDS_REVIEW'
    name=value(ctx,r,path+'/MediaStreamName');fmt=value(ctx,r,path+'/EncodingName')
    rows=value(ctx,parent,'/properties/MediaStreams')
    if not literal(name) or not literal(fmt) or not isinstance(rows,list) or len(rows)>100:return 'NEEDS_REVIEW'
    kinds=[];unknown=False
    for i in range(len(rows)):
        base=f'/properties/MediaStreams/{i}'
        other=value(ctx,parent,base+'/MediaStreamName')
        if not literal(other):unknown=True
        elif name==other:kinds.append(value(ctx,parent,base+'/MediaStreamType'))
    if unknown or len(kinds)!=1 or not isinstance(kinds[0],str):return 'NEEDS_REVIEW'
    allowed={'video':{'raw','jxsv'},'audio':{'pcm'},'ancillary-data':{'smpte291'}}.get(kinds[0])
    if allowed is None or fmt not in ('raw','jxsv','pcm','smpte291'):return 'NEEDS_REVIEW'
    return 'PASS' if fmt in allowed else 'FAIL'


def cdi(ctx,r,parent,path):
    params=value(ctx,r,path+'/EncodingParameters')
    if resolved(r) and params is ABSENT:return 'NOT_APPLICABLE'
    if parent is None or not isinstance(params,dict) or '$state' in params:return 'NEEDS_REVIEW'
    if value(ctx,parent,'/properties/Source/Protocol')=='cdi':return 'PASS'
    return 'NEEDS_REVIEW'


@resource_check('AWS::MediaConnect::FlowOutput')
def evaluate_mediaconnect_output_context(design,resource):
    if resource.type!='AWS::MediaConnect::FlowOutput':return []
    ctx=_Context(design,resource);parent=flow(ctx,resource)
    checks=[('MEDIACONNECT_OUTPUT_NDI_ENABLED','/properties/Protocol',ndi(ctx,resource,parent))]
    for path in expand(ctx,resource,'/properties/MediaStreamOutputConfigurations/*'):
        valid=path.count('/')==3
        checks.extend([('MEDIACONNECT_OUTPUT_ENCODING_MEDIA_TYPE',path,encoding(ctx,resource,parent,path) if valid else 'NEEDS_REVIEW'),('MEDIACONNECT_OUTPUT_CDI_ENCODING_CONTEXT',path,cdi(ctx,resource,parent,path) if valid else 'NEEDS_REVIEW')])
    result=[]
    for rule,path,verdict in checks:
        f=ctx.finding(rule,path,verdict,'Resolve an explicitly linked flow. NDI output requires NdiState ENABLED; compare media-stream encoding with its named video/audio/ancillary type. EncodingParameters applicability is established by a declared inline CDI source. Missing external sources never prove absence. PASS concerns declared configuration only; exact video codec transport support, literal deployed flow identity and live media behavior remain reviewable.')
        f['source_checked_at']='2026-10-04';result.append(f)
    return result
