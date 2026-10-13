"""Checks for AWS::S3Express::AccessPoint."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

SOURCES = {
    'S3EXPRESS_PREFIX_BYTES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3express-accesspoint-scope.html',
        'https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html',
    ],
}


@resource_check('AWS::S3Express::AccessPoint')
def evaluate_s3express_prefix_bytes(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::S3Express::AccessPoint':
        path='/properties/Scope/Prefixes';raw=get(path)
        if raw is not ABSENT:
            pending=not isinstance(raw,list);total=0
            for i in range(len(raw)) if isinstance(raw,list) else ():
                prefix=get(path+'/'+str(i))
                if isinstance(prefix,str) and '${' not in prefix and '{{' not in prefix:
                    try:total+=len(prefix.encode('utf8'))
                    except UnicodeEncodeError:pending=True
                else:pending=True
            emit('S3EXPRESS_PREFIX_BYTES',path,'FAIL' if total>=256 else 'NEEDS_REVIEW' if pending else 'PASS','sum of explicit UTF-8 prefix bytes must be below 256; no Unicode normalization, URL decoding or implicit wildcard expansion; unresolved and invalid Unicode strings remain under review')
    return results
