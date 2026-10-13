"""Account and Region scope of explicit ARNs and linked resources."""
import re
from .context_values import linked, value
from .field_reads import ABSENT, UNKNOWN

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'KMS_ALIAS_TARGET_SCOPE': [CF + 'aws-resource-kms-alias.html', CF + 'aws-resource-kms-replicakey.html'],
}


def scope_findings(ctx, resource, specs):
    """Compare the account/Region of explicit ARNs or linked resources with the resource scope."""
    results = []
    for path, service, target_type, compare, rule in specs:
        raw = value(ctx, resource, path)
        if raw is ABSENT:
            continue
        account, region = None, None
        target = linked(ctx, resource, path, target_type)
        if target is None and rule == 'KMS_ALIAS_TARGET_SCOPE':
            target = linked(ctx, resource, path, 'AWS::KMS::ReplicaKey')
        if target:
            account, region = target.scope.account, target.scope.region
        elif isinstance(raw, str):
            match = re.fullmatch(r'arn:[a-z0-9-]+:' + service + r':([a-z0-9-]*):(\d{12}):.+', raw)
            if match:
                region, account = match.groups()
        comparisons = []
        if compare in ('account', 'both'):
            comparisons.append(None if not account or not re.fullmatch(r'\d{12}', resource.scope.account) else account == resource.scope.account)
        if compare in ('region', 'both'):
            comparisons.append(None if not region or not re.fullmatch(r'[a-z]+(?:-[a-z]+)+-\d+', resource.scope.region) else region == resource.scope.region)
        verdict = 'FAIL' if False in comparisons else 'NEEDS_REVIEW' if None in comparisons else 'PASS'
        results.append(ctx.finding(rule, path, verdict,
            'compares explicit ARN or linked-resource scope only; existence, ownership class and permissions remain separate'))
    return results


def symmetric_key_verdict(ctx, key):
    unsupported = {'RSA_2048','RSA_3072','RSA_4096','ECC_NIST_P256','ECC_NIST_P384','ECC_NIST_P521',
        'ECC_SECG_P256K1','ECC_NIST_EDWARDS25519','SM2','ML_DSA_44','ML_DSA_65','ML_DSA_87',
        'HMAC_224','HMAC_256','HMAC_384','HMAC_512'}
    spec = value(ctx, key, '/properties/KeySpec') if key else UNKNOWN
    usage = value(ctx, key, '/properties/KeyUsage') if key else UNKNOWN
    if spec is ABSENT:
        spec = 'SYMMETRIC_DEFAULT'
    if usage is ABSENT:
        usage = 'ENCRYPT_DECRYPT'
    bad = (isinstance(spec, str) and spec in unsupported) or usage in ('SIGN_VERIFY','GENERATE_VERIFY_MAC','KEY_AGREEMENT')
    verdict = 'FAIL' if bad else 'PASS' if spec == 'SYMMETRIC_DEFAULT' and usage == 'ENCRYPT_DECRYPT' else 'NEEDS_REVIEW'
    return verdict
