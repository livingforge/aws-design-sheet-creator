"""Checks for AWS::MediaLive::Channel."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from ..common.numbers import number

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'MEDIALIVE_VIDEO_EVEN': [CF+'aws-properties-medialive-channel-videodescription.html',CF+'aws-properties-medialive-channel-videopositionrectangle.html'],
    'MEDIALIVE_VIDEO_BORDER': ['https://docs.aws.amazon.com/medialive/latest/apireference/channels.html'],
    'MEDIALIVE_CAPTION_RECTANGLE': [CF+'aws-properties-medialive-channel-captionrectangle.html'],
}


@resource_check('AWS::MediaLive::Channel')
def evaluate_medialive_channel_geometry(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::MediaLive::Channel':
        for base in expand(ctx,resource,'/properties/EncoderSettings/VideoDescriptions/*'):
            fields=['Width','Height']+[owner+'/'+key for owner in ('CropRectangle','OutputPositionRectangle') for key in ('Width','Height','X','Y')]
            for key in fields:
                path=base+'/'+key;raw=get(path)
                if raw is not ABSENT:
                    emit('MEDIALIVE_VIDEO_EVEN',path,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if raw%2==0 else 'FAIL','explicit video dimensions and position rectangle members must be even; source-derived dimensions and unknown values remain under review')
            path=base+'/Border';border=get(path)
            if border is not ABSENT:
                verdict='NEEDS_REVIEW'
                if type(border) is int:
                    dimensions=[get(base+'/'+key) for key in ('Width','Height')]
                    invalid=not 0<=border<=100 or border%2!=0 or any(type(x) is int and x<=2*border for x in dimensions)
                    verdict='FAIL' if invalid else 'PASS' if all(type(x) is int for x in dimensions) else 'NEEDS_REVIEW'
                emit('MEDIALIVE_VIDEO_BORDER',path,verdict,'border must be even in 0..100 and explicit width/height must each exceed twice border; inherited dimensions, output-position compatibility and unknown values remain separate')
        selectors=list(expand(ctx,resource,'/properties/InputAttachments/*/InputSettings/CaptionSelectors/*'))
        captions=list(expand(ctx,resource,'/properties/EncoderSettings/CaptionDescriptions/*'))
        for selector in selectors:
            base=selector+'/SelectorSettings/TeletextSourceSettings/OutputRectangle'
            if get(base) is ABSENT:continue
            name=get(selector+'/Name');known_names=[get(p+'/Name') for p in selectors]
            applies=False
            if literal(name) and all(literal(x) for x in known_names) and known_names.count(name)==1:
                for caption in captions:
                    if get(caption+'/CaptionSelectorName')!=name:continue
                    if any(isinstance(get(caption+'/DestinationSettings/'+key),dict) for key in ('EbuTtDDestinationSettings','TtmlDestinationSettings')):applies=True
            for offset,size in (('LeftOffset','Width'),('TopOffset','Height')):
                a=number(get(base+'/'+offset));b=number(get(base+'/'+size));verdict='NEEDS_REVIEW'
                if applies and a is not None and b is not None and a>=0 and b>=0:verdict='PASS' if a+b<=100 else 'FAIL'
                emit('MEDIALIVE_CAPTION_RECTANGLE',base+'/'+size,verdict,'offset plus size must be at most 100 for a uniquely named input selector explicitly used by TTML/EBU-TT-D output; unknown values, ambiguous selectors and other output formats remain under review')
    return results
