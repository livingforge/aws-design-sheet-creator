"""Prove declared Connect instance security-key overcapacity without live inventory."""
import re
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import UnsupportedAlgorithm
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import literal
from ..common.scoped_resolution import resolved

SOURCES={'CONNECT_INSTANCE_SECURITY_KEY_LIMIT':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-connect-securitykey.html','https://docs.aws.amazon.com/connect/latest/APIReference/API_AssociateSecurityKey.html']}


def instance(ctx,r):
    if not resolved(r):return None
    other=linked(ctx,r,'/properties/InstanceId','AWS::Connect::Instance')
    if resolved(other):return ('resource',other.id)
    raw=value(ctx,r,'/properties/InstanceId')
    m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:connect:([a-z0-9-]+):([0-9]{12}):instance/[a-zA-Z0-9-]+',raw) if literal(raw) and len(raw)<=100 else None
    return ('arn',raw) if m and (m[1],m[2])==(r.scope.region,r.scope.account) else None


def public_key(raw):
    if not literal(raw) or len(raw)>1024:return None
    try:
        key=serialization.load_pem_public_key(raw.encode('ascii'))
        return key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError,TypeError,UnicodeError,UnsupportedAlgorithm):return None


@resource_check('AWS::Connect::SecurityKey')
def evaluate_connect_security_count(design,resource):
    if resource.type!='AWS::Connect::SecurityKey':return []
    ctx=_Context(design,resource);owner=instance(ctx,resource);keys=set()
    if owner:
        for other in design.resources:
            if other.type!=resource.type or other.scope!=resource.scope or instance(ctx,other)!=owner:continue
            key=public_key(value(ctx,other,'/properties/Key'))
            if key is not None:keys.add(key)
    verdict='FAIL' if len(keys)>2 else 'NEEDS_REVIEW'
    f=ctx.finding('CONNECT_INSTANCE_SECURITY_KEY_LIMIT','/properties/InstanceId',verdict,'An instance permits at most two security keys. More than two distinct explicit PEM public keys for one comparable instance identity exceed the limit. Canonical DER removes PEM formatting duplicates. Fewer known keys do not prove absence of external keys, conditional resources or other aliases; key algorithm acceptance and live associations are not certified.')
    f['source_checked_at']='2026-10-04';return [f]
