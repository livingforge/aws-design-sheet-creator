"""Checks for AWS::XRay::SamplingRule."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'XRAY_SAMPLING_ATTRIBUTES': [CF+'aws-properties-xray-samplingrule-samplingrule.html'],
}


@resource_check('AWS::XRay::SamplingRule')
def evaluate_xray_sampling_attributes(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::XRay::SamplingRule':
        path='/properties/SamplingRule/Attributes';raw=get(path)
        if raw is not ABSENT:
            pending=not isinstance(raw,dict);invalid=False;known_keys=0
            for key in raw if isinstance(raw,dict) else ():
                if not isinstance(key,str) or '${' in key or '{{' in key:pending=True;continue
                known_keys+=1;invalid|=not 1<=len(key)<=32
                if '/' in key or '~' in key:pending=True;continue
                item=get(path+'/'+key)
                if isinstance(item,str) and '${' not in item and '{{' not in item:invalid|=not 1<=len(item)<=32
                else:pending=True
            invalid|=known_keys>5
            emit('XRAY_SAMPLING_ATTRIBUTES',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','sampling attributes allow at most five known map keys, each key/value 1..32 characters; escaped keys, dynamic values and actual matching behavior remain under review')
    return results
