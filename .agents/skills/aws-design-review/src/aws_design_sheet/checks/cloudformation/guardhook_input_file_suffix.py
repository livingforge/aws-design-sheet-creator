"""Checks for AWS::CloudFormation::GuardHook."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GUARDHOOK_INPUT_FILE_SUFFIX': [CF+'aws-properties-cloudformation-guardhook-options.html',CF+'aws-properties-cloudformation-guardhook-s3location.html'],
}


@resource_check('AWS::CloudFormation::GuardHook')
def evaluate_cloudformation_guardhook_input_file_suffix(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::CloudFormation::GuardHook':
        root='/properties/Options/InputParams';raw=get(root)
        paths=[root+'/'+str(i) for i in range(len(raw))] if isinstance(raw,list) else [] if raw is ABSENT else [root]
        for base in paths:
            p=base+'/Uri';uri=get(p);v='NEEDS_REVIEW'
            if literal(uri) and re.fullmatch(r's3://[^/]+/[^?#%]+',uri):
                suffixes=('.yaml','.json','.zip','.tar.gz')
                v='PASS' if uri.endswith(suffixes) else 'NEEDS_REVIEW' if uri.lower().endswith(suffixes) else 'FAIL'
            emit('GUARDHOOK_INPUT_FILE_SUFFIX',p,v,'literal S3 input objects use documented file suffixes; uppercase/encoded/unknown URI forms and duplicate top-level file keys held')
    return results
