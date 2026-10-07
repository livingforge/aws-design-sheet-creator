"""Checks for AWS::Transfer::Connector."""
import base64
import binascii
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'TRANSFER_HOST_KEY_TEXT': [CF+'aws-properties-transfer-connector-sftpconfig.html'],
}
KEY_TYPES={'ssh-rsa','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521'}


def host_key_text(raw,egress):
    if not literal(raw) or any(c in raw for c in '\r\n\t'):return 'NEEDS_REVIEW'
    parts=raw.split();host=False
    if not parts:return 'NEEDS_REVIEW'
    # Recognize the documented hostname-prefixed keyscan form without contacting it.
    if len(parts)>=3 and parts[1] in KEY_TYPES:
        host=True;parts=parts[1:]
    if parts[0] not in KEY_TYPES:
        return 'FAIL' if parts[0].startswith(('ssh-','ecdsa-','sk-')) else 'NEEDS_REVIEW'
    if len(parts)!=2:return 'FAIL' if len(parts)>2 else 'NEEDS_REVIEW'
    try:body=base64.b64decode(parts[1],validate=True)
    except (ValueError,binascii.Error):return 'NEEDS_REVIEW'
    if not body:return 'NEEDS_REVIEW'
    if host:return 'FAIL' if egress=='VPC_LATTICE' else 'PASS' if egress=='SERVICE_MANAGED' else 'NEEDS_REVIEW'
    return 'PASS'


@resource_check('AWS::Transfer::Connector')
def evaluate_transfer_host_key_text(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Transfer::Connector':
        egress=get('/properties/EgressType')
        for path in expand(ctx,resource,'/properties/SftpConfig/TrustedHostKeys/*'):
            emit('TRANSFER_HOST_KEY_TEXT',path,host_key_text(get(path),egress),'checks only documented RSA/ECDSA key-type, decodable nonempty Base64 body, absence of comments and VPC_LATTICE hostname prohibition; key wire structure, cryptographic validity and host authenticity are not certified; no network or secret access')
    return results
