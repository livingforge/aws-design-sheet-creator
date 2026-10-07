"""Checks for AWS::IVS::EncoderConfiguration."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

SOURCES = {
    'IVS_VIDEO_EVEN': ['https://docs.aws.amazon.com/ivs/latest/RealTimeAPIReference/API_Video.html'],
    'IVS_VIDEO_PIXEL_LIMIT': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ivs-encoderconfiguration-video.html',
    ],
}


@resource_check('AWS::IVS::EncoderConfiguration')
def evaluate_ivs_encoder_configuration(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    root='/properties/Video'
    if get(root) is not ABSENT:
        dimensions=[]
        for key,default in (('Width',1280),('Height',720)):
            path=root+'/'+key;raw=get(path)
            if raw is ABSENT:raw=default
            else:emit('IVS_VIDEO_EVEN',path,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if raw%2==0 else 'FAIL','explicit video width and height must be even; unknown/noninteger values remain under review')
            dimensions.append(raw)
        verdict='NEEDS_REVIEW'
        if all(type(x) is int and x>0 for x in dimensions):
            verdict='PASS' if dimensions[0]*dimensions[1]<=2073600 else 'FAIL'
        emit('IVS_VIDEO_PIXEL_LIMIT',root,verdict,'width times height must not exceed 2073600 pixels; only absent members use documented defaults 1280/720; unknown values never use defaults')
    return results
