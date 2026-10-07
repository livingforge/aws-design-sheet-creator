"""Checks for AWS::MediaLive::Channel."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'MEDIALIVE_HIGH_RES_H265': [CF+'aws-properties-medialive-channel-h265settings.html'],
}


@resource_check('AWS::MediaLive::Channel')
def evaluate_medialive_high_res_h265(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::MediaLive::Channel':
        for base in expand(ctx,resource,'/properties/EncoderSettings/VideoDescriptions/*'):
            width=get(base+'/Width');height=get(base+'/Height');codec=base+'/CodecSettings/H265Settings'
            if get(codec) is ABSENT:continue
            for key,expected in [('GopBReference','DISABLED'),('SubgopLength','FIXED'),('GopNumBFrames',2)]:
                p=codec+'/'+key;raw=get(p);v='NEEDS_REVIEW'
                if type(width) is int and type(height) is int and width>=1920 and height>1080:
                    if type(raw) is type(expected):v='PASS' if raw==expected else 'FAIL'
                emit('MEDIALIVE_HIGH_RES_H265',p,v,'explicit dimensions at least 1920 wide and over 1080 high require specified H265 GOP values; omitted/source-derived or other resolution interpretations held')
    return results
