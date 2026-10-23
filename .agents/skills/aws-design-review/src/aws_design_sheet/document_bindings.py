"""Local, non-secret values for EXTERNAL_REF settings, used only by the opt-in evaluation.

A binding file names an external reference and the value the designer expects it to
take (an existing VPC ID, a KMS key ARN). Values are read from the file; nothing is
fetched from AWS, so existence, ownership and current state stay unverified. Secret
references and sensitive properties are never bound.
"""
import hashlib
import json
import re

FORMAT = '1.0'
MAX_BINDINGS = 5000
NOTE = 'Value supplied by a local binding file; existence, ownership and current state in AWS are not verified.'
ARN = re.compile(r'^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b):[^:]*:([^:]*):')
# Properties whose ARN must be in one fixed region whatever the resource's region.
FIXED_REGION = {
    ('AWS::CloudFront::Distribution', '/DistributionConfig/ViewerCertificate/AcmCertificateArn'): 'us-east-1',
    ('AWS::CloudFront::Distribution', '/DistributionConfig/WebACLId'): 'us-east-1',
}
# Properties that point to another region by design; a different region is recorded, not refused.
CROSS_REGION = {
    ('AWS::Backup::BackupPlan', '/BackupPlan/BackupPlanRule/*/CopyActions/*/DestinationBackupVaultArn'),
    ('AWS::KMS::ReplicaKey', '/PrimaryKeyArn'),
    ('AWS::RDS::DBInstance', '/SourceDBInstanceIdentifier'),
    ('AWS::RDS::DBCluster', '/ReplicationSourceIdentifier'),
}


class BindingError(ValueError):
    """Message carries codes and references only, never bound values."""


def token(value):
    return str(value).replace('~', '~0').replace('/', '~1')


def parts_of(path):
    return [int(p) if p.isdigit() else p.replace('~1', '/').replace('~0', '~') for p in path.split('/')[2:]]


def partition(region):
    return 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'


def strings(value):
    if isinstance(value, str):yield value
    elif isinstance(value, list):
        for v in value:yield from strings(v)
    elif isinstance(value, dict):
        for v in value.values():yield from strings(v)


def region_check(kind, path, value, region):
    """None when every ARN fits the resource's region, else the mismatch; global ARNs have no region."""
    pattern = '/' + '/'.join('*' if p.isdigit() else p for p in path.split('/')[2:])
    expected = FIXED_REGION.get((kind, pattern), region)
    found = []
    for text in strings(value):
        m = ARN.match(text)
        if not m:continue
        if m.group(1) != partition(expected) or (m.group(2) and m.group(2) != expected):
            found.append({'arn_partition': m.group(1), 'arn_region': m.group(2) or None})
    if not found:return None
    return {'expected_region': expected, 'found': found, 'cross_region_by_design': (kind, pattern) in CROSS_REGION
            and all(f['arn_partition'] == partition(region) for f in found)}


def uses(document):
    """Every EXTERNAL_REF/SECRET_REF leaf of the selected environment's effective settings."""
    from .document_v11 import SchemaSetting
    found = []

    def visit(setting, item, path):
        if setting.status == 'NOT_APPLICABLE' or setting.mode == 'OMITTED':return
        if setting.mode == 'COMPOSITE':
            def walk(value, sub):
                if isinstance(value, dict):
                    if set(value) == {'$design'}:
                        visit(SchemaSetting.model_validate(value['$design']), item, sub);return
                    for k, v in value.items():walk(v, sub + '/' + token(k))
                elif isinstance(value, list):
                    for i, v in enumerate(value):walk(v, sub + '/' + str(i))
            walk(setting.value, path);return
        if setting.mode in ('EXTERNAL_REF', 'SECRET_REF') and setting.status == 'DECIDED':
            found.append({'ref': setting.ref, 'mode': setting.mode, 'classification': setting.classification,
                          'item_id': item.item_id, 'resource_id': item.resource_id, 'path': path})
    for item in document.items:
        if item.origin != 'cfn_only':visit(item.expected, item, '/properties/' + token(item.name))
    return found


def read_bindings(path, document):
    """Validate a binding file against the document; return the per-use binding report."""
    from .document_catalog import catalog
    from .document_normalize import secret_literal
    from .document_v11 import sensitive
    if path is None:return {'status': 'NOT_PROVIDED', 'uses': [], 'unused_refs': [], 'counts': {}}
    raw = path.read_bytes();data = json.loads(raw)
    if not isinstance(data, dict) or data.get('binding_version') != FORMAT or not isinstance(data.get('bindings'), list):
        raise BindingError('UNSUPPORTED_BINDING_FILE')
    if 'environment' in data and data['environment'] != document.environment_id:raise BindingError('BINDING_ENVIRONMENT_MISMATCH')
    if len(data['bindings']) > MAX_BINDINGS:raise BindingError('TOO_MANY_BINDINGS')
    values = {}
    for entry in data['bindings']:
        if not isinstance(entry, dict) or set(entry) - {'ref', 'value', 'source'} or not isinstance(entry.get('ref'), str) \
                or not entry['ref'] or len(entry['ref']) > 256 or 'value' not in entry or entry['value'] is None:
            raise BindingError('INVALID_BINDING')
        if 'source' in entry and not isinstance(entry['source'], str):raise BindingError('INVALID_BINDING_SOURCE')
        if entry['ref'] in values:raise BindingError('DUPLICATE_BINDING:' + entry['ref'])
        if secret_literal(entry['value']):raise BindingError('SECRET_LIKE_BINDING:' + entry['ref'])
        values[entry['ref']] = entry
    found = uses(document)
    for use in found:
        if use['ref'] in values and (use['mode'] == 'SECRET_REF' or use['classification'] == 'SECRET'):
            raise BindingError('SECRET_REFERENCE_CANNOT_BE_BOUND:' + use['ref'])
    resources = {r.id: r for r in document.design.resources}
    env = next(e for e in document.design.environments if e.id == document.environment_id)
    rows = []
    for use in found:
        if use['mode'] != 'EXTERNAL_REF':continue
        row = {k: use[k] for k in ('ref', 'item_id', 'resource_id', 'path')}
        entry = values.get(use['ref'])
        resource = resources[use['resource_id']];parts = parts_of(use['path'])
        if entry is None:row['status'] = 'UNBOUND'
        elif sensitive(resource.type, parts):raise BindingError('SENSITIVE_PROPERTY_CANNOT_BE_BOUND:' + use['ref'])
        else:
            region = getattr(resource, 'region', None) or env.region
            try:
                catalog(region).shape(resource.type, parts, entry['value'])
            except ValueError:
                row['status'] = 'SHAPE_MISMATCH'
            else:
                mismatch = region_check(resource.type, use['path'], entry['value'], region)
                if mismatch and not mismatch['cross_region_by_design']:
                    row.update(status='REGION_MISMATCH', region=mismatch)
                else:
                    row.update(status='BOUND', value=entry['value'], source=entry.get('source', ''))
                    if mismatch:row['cross_region'] = mismatch
        rows.append(row)
    used = {u['ref'] for u in found}
    counts = {}
    for row in rows:counts[row['status']] = counts.get(row['status'], 0) + 1
    return {'status': 'PROVIDED', 'sha256': hashlib.sha256(raw).hexdigest(), 'uses': rows,
            'unused_refs': sorted(set(values) - used), 'counts': dict(sorted(counts.items())), 'scope': NOTE}


def applied(report):
    """{(resource_id, path): value} of bindings whose JSON type fits the pinned schema."""
    return {(r['resource_id'], r['path']): r['value'] for r in report.get('uses', []) if r['status'] == 'BOUND'}
