"""KMS key-type classification and base64 syntax checks."""
import base64
import binascii
import re
from .context_values import linked, value
from .literals import literal

ASYMMETRIC=('RSA_2048','RSA_3072','RSA_4096','ECC_NIST_P256','ECC_NIST_P384','ECC_NIST_P521','ECC_SECG_P256K1','SM2')


def base64_syntax(raw):
    if not literal(raw) or len(raw)>256000:return 'NEEDS_REVIEW'
    # Whitespace, URL-safe alphabets and unpadded spellings can depend on decoder
    # policy. Only claim ordinary canonical Base64, not a service parser policy.
    if any(c.isspace() or c in '-_' for c in raw):return 'NEEDS_REVIEW'
    if not re.fullmatch(r'[A-Za-z0-9+/=]+',raw):return 'FAIL'
    if len(raw)%4:return 'NEEDS_REVIEW'
    try:decoded=base64.b64decode(raw,validate=True)
    except (ValueError,binascii.Error):return 'FAIL'
    return 'PASS' if base64.b64encode(decoded).decode('ascii')==raw else 'NEEDS_REVIEW'


def key_type(ctx,resource,path):
    if resource.template is not None and resource.template.state.value!='KNOWN':return 'NEEDS_REVIEW'
    key=linked(ctx,resource,path,'AWS::KMS::Key')
    if key is None or key.template is not None and key.template.state.value!='KNOWN':return 'NEEDS_REVIEW'
    spec=value(ctx,key,'/properties/KeySpec')
    return 'FAIL' if spec in ASYMMETRIC else 'PASS' if spec=='SYMMETRIC_DEFAULT' else 'NEEDS_REVIEW'
