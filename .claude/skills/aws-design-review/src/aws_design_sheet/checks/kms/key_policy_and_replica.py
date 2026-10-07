"""Checks for AWS::KMS::Key, AWS::KMS::ReplicaKey."""
import json
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.json_constants import reject_constant
from ..common.partitions import public_partition

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'KMS_POLICY_PRINCIPALS_PRESENT': [CF + 'aws-resource-kms-key.html', CF + 'aws-resource-kms-replicakey.html'],
    'KMS_SM2_CHINA_REGION': [CF + 'aws-resource-kms-key.html'],
    'KMS_REPLICA_REGION_PARTITION': [CF + 'aws-resource-kms-replicakey.html'],
    'KMS_REPLICA_DESIGN_DUPLICATE': [CF + 'aws-resource-kms-replicakey.html'],
    'KMS_REPLICA_PRIMARY_DECLARATION': [CF + 'aws-resource-kms-replicakey.html', CF + 'aws-resource-kms-key.html'],
}


def principal_value(raw):
    if isinstance(raw, str):
        return None if '{{' in raw else bool(raw)
    if isinstance(raw, list):
        parts = [None if not isinstance(v, str) or '{{' in v else bool(v) for v in raw]
        return True if True in parts else None if None in parts else False
    return None


def principal_shape(raw):
    if isinstance(raw, dict):
        if any(k not in ('AWS', 'Service', 'Federated', 'CanonicalUser') for k in raw):
            return None
        parts = [principal_value(v) for v in raw.values()]
        return True if True in parts else None if None in parts else False
    return principal_value(raw)


def key_policy(ctx, resource):
    path = '/properties/KeyPolicy'
    raw = value(ctx, resource, path)
    if raw is ABSENT:
        return []
    pending, bad = raw is UNKNOWN, False
    if isinstance(raw, str):
        if '{{resolve:' in raw:
            pending = True
        else:
            try:
                raw = json.loads(raw, parse_constant=reject_constant)
            except (ValueError, RecursionError):
                bad = True
    if not pending and not bad:
        if not isinstance(raw, dict):
            bad = True
        elif any(k in ('$state', 'Ref') or k.startswith('Fn::') for k in raw):
            pending = True
        else:
            statements = raw.get('Statement')
            if isinstance(statements, dict):
                statements = [statements]
            if not isinstance(statements, list):
                bad = True
            else:
                for statement in statements:
                    if not isinstance(statement, dict):
                        bad = True
                    elif any(k in ('$state', 'Ref', 'NotPrincipal') or k.startswith('Fn::') for k in statement):
                        pending = True
                    elif 'Principal' not in statement:
                        bad = True
                    else:
                        status = principal_shape(statement['Principal'])
                        bad |= status is False
                        pending |= status is None
    return [ctx.finding('KMS_POLICY_PRINCIPALS_PRESENT', path,
        'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS',
        'each explicit policy statement must contain a nonempty principal; caller authorization and principal existence are not evaluated')]


@resource_check('AWS::KMS::Key', 'AWS::KMS::ReplicaKey')
def kms_local(design, resource):
    ctx = _Context(design, resource)
    results = key_policy(ctx, resource)
    if resource.type == 'AWS::KMS::Key':
        if value(ctx, resource, '/properties/KeySpec') == 'SM2':
            partition = public_partition(resource.scope.region)
            verdict = 'PASS' if partition == 'aws-cn' else 'FAIL' if partition else 'NEEDS_REVIEW'
            results.append(ctx.finding('KMS_SM2_CHINA_REGION', '/properties/KeySpec', verdict,
                'SM2 is restricted to China Regions; this does not certify availability of other key types'))
        return results
    path = '/properties/PrimaryKeyArn'
    primary = replica_primary(ctx, resource, path)
    multi = value(ctx, primary, '/properties/MultiRegion') if primary else UNKNOWN
    results.append(ctx.finding('KMS_REPLICA_PRIMARY_DECLARATION', path,
        'PASS' if multi is True else 'FAIL' if multi is False or multi is ABSENT else 'NEEDS_REVIEW',
        'checks a declared multi-Region primary Key in another Region of the same partition/account; runtime primary status and availability remain external'))
    arn = value(ctx, resource, path)
    match = re.fullmatch(r'arn:([a-z0-9-]+):kms:([a-z0-9-]+):([0-9]{12}):key/[^{}\s]+', arn) if isinstance(arn, str) else None
    partition = public_partition(resource.scope.region)
    verdict = 'NEEDS_REVIEW'
    if match and partition:
        verdict = 'FAIL' if match[1] != partition or match[2] == resource.scope.region else 'PASS'
    results.append(ctx.finding('KMS_REPLICA_REGION_PARTITION', path, verdict,
        'literal primary key ARN must identify another Region in the same partition; primary status, existence and regional key support remain external'))
    duplicates = []
    if match or primary:
        for other in design.resources:
            if other.id == resource.id or other.type != resource.type:
                continue
            if other.scope.account != resource.scope.account or other.scope.region != resource.scope.region:
                continue
            other_arn = value(ctx, other, path)
            other_primary = replica_primary(ctx, other, path) if primary else None
            if match and other_arn == arn or primary and other_primary and primary.id == other_primary.id:
                duplicates.append(other.id)
    results.append(ctx.finding('KMS_REPLICA_DESIGN_DUPLICATE', path,
        'FAIL' if duplicates else 'NEEDS_REVIEW',
        'another design replica uses this primary in the same account/Region: ' + ', '.join(duplicates) if duplicates else
        'no proven design duplicate; existing regional replicas and unresolved aliases remain unverified'))
    return results


def replica_primary(ctx, resource, path):
    refs = [r for r in ctx.design.relations if r.source_resource_id == resource.id and r.source_path == path]
    if len(refs) != 1:
        return None
    primary = ctx.by_id.get(refs[0].target_resource_id)
    if not primary or not re.fullmatch(r'[0-9]{12}', resource.scope.account):
        return None
    partition = public_partition(resource.scope.region)
    if not partition or public_partition(primary.scope.region) != partition or primary.scope.region == resource.scope.region:
        return None
    # Replication explicitly crosses Regions. Relax only this dimension on a copy;
    # linked() still checks type, account, environment, conditions and value state.
    scope = resource.scope.model_copy(update={'region': primary.scope.region})
    source = resource.model_copy(update={'scope': scope})
    return linked(ctx, source, path, 'AWS::KMS::Key')
