"""Signing settings of linked customer managed keys and replica primaries."""
from .context_values import linked, value
from .field_reads import ABSENT
from .key_types_and_base64 import ASYMMETRIC
from .kms_key_types import HMAC, SIGNING_ONLY, primary_key
from .scoped_resolution import resolved


def signing_settings(ctx,resource,path,allowed_specs):
    if not resolved(resource):return 'NEEDS_REVIEW'
    key=linked(ctx,resource,path,'AWS::KMS::Key')
    if key is None:
        replica=linked(ctx,resource,path,'AWS::KMS::ReplicaKey')
        if not resolved(replica):return 'NEEDS_REVIEW'
        key=primary_key(ctx,replica)
    if not resolved(key):return 'NEEDS_REVIEW'
    spec=value(ctx,key,'/properties/KeySpec');usage=value(ctx,key,'/properties/KeyUsage')
    if spec is ABSENT:spec='SYMMETRIC_DEFAULT'
    if usage is ABSENT:usage='ENCRYPT_DECRYPT'
    if usage in ('ENCRYPT_DECRYPT','GENERATE_VERIFY_MAC','KEY_AGREEMENT'):return 'FAIL'
    if spec in ('SYMMETRIC_DEFAULT',)+ASYMMETRIC+HMAC+SIGNING_ONLY and spec not in allowed_specs:return 'FAIL'
    return 'PASS' if spec in allowed_specs and usage=='SIGN_VERIFY' else 'NEEDS_REVIEW'
