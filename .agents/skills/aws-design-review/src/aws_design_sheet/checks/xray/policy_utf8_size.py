"""Checks for AWS::XRay::ResourcePolicy."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'XRAY_POLICY_UTF8_SIZE': [CF+'aws-resource-xray-resourcepolicy.html','https://docs.aws.amazon.com/xray/latest/api/API_PutResourcePolicy.html'],
}


def policy_bytes(raw):
    if not literal(raw) or len(raw)>256000:return 'NEEDS_REVIEW'
    try:size=len(raw.encode('utf8'))
    except UnicodeEncodeError:return 'NEEDS_REVIEW'
    # The prose says 5KB while the string schema says 5120 characters.
    # Preserve the decimal/binary boundary ambiguity instead of inventing it.
    return 'PASS' if size<=5000 else 'FAIL' if size>5120 else 'NEEDS_REVIEW'


@resource_check('AWS::XRay::ResourcePolicy')
def evaluate_xray_policy_utf8_size(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::XRay::ResourcePolicy':
        path='/properties/PolicyDocument';raw=value(ctx,resource,path)
        if raw is not ABSENT:emit('XRAY_POLICY_UTF8_SIZE',path,policy_bytes(raw),'bounded UTF-8 byte size only; 5001..5120-byte boundary ambiguity, invalid Unicode, dynamic/oversized input, JSON/policy semantics and effective permissions remain held')
    return results
