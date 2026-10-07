"""Closed ledger follow-up batch: declaration collisions and linked encryption keys."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scope import symmetric_key_verdict

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
NAMES = {
    'AWS::CloudFront::OriginRequestPolicy': ('CF_ORIGIN_POLICY_COLLISION', ('OriginRequestPolicyConfig/Name',), 'aws-properties-cloudfront-originrequestpolicy-originrequestpolicyconfig.html'),
    'AWS::CloudFront::ResponseHeadersPolicy': ('CF_RESPONSE_POLICY_COLLISION', ('ResponseHeadersPolicyConfig/Name',), 'aws-properties-cloudfront-responseheaderspolicy-responseheaderspolicyconfig.html'),
    'AWS::CloudWatch::AlarmMuteRule': ('CW_MUTE_NAME_COLLISION', ('Name',), 'aws-resource-cloudwatch-alarmmuterule.html'),
    'AWS::CloudWatch::CompositeAlarm': ('CW_COMPOSITE_NAME_COLLISION', ('AlarmName',), 'aws-resource-cloudwatch-compositealarm.html'),
    'AWS::CloudWatch::MetricStream': ('CW_STREAM_NAME_COLLISION', ('Name',), 'aws-resource-cloudwatch-metricstream.html'),
    'AWS::CloudWatch::OTelEnrichment': ('CW_OTEL_DECLARATION_COLLISION', (), 'aws-resource-cloudwatch-otelenrichment.html'),
    'AWS::IAM::VirtualMFADevice': ('IAM_MFA_NAME_PATH_COLLISION', ('VirtualMfaDeviceName', 'Path'), 'aws-resource-iam-virtualmfadevice.html'),
    'AWS::RDS::DBClusterParameterGroup': ('RDS_CLUSTER_PARAMETER_NAME_COLLISION', ('DBClusterParameterGroupName',), 'aws-resource-rds-dbclusterparametergroup.html'),
    'AWS::RDS::DBProxy': ('RDS_PROXY_NAME_COLLISION', ('DBProxyName',), 'aws-resource-rds-dbproxy.html'),
    'AWS::RDS::DBProxyEndpoint': ('RDS_PROXY_ENDPOINT_NAME_COLLISION', ('DBProxyEndpointName',), 'aws-resource-rds-dbproxyendpoint.html'),
    'AWS::RDS::CustomDBEngineVersion': ('RDS_CEV_IDENTITY_COLLISION', ('Engine', 'EngineVersion'), 'aws-resource-rds-customdbengineversion.html'),
}
KEYS = {
    'AWS::RDS::CustomDBEngineVersion': ('RDS_CEV_KEY_TYPE', 'KMSKeyId', 'aws-resource-rds-customdbengineversion.html'),
    'AWS::S3::StorageLens': ('S3_STORAGE_LENS_KEY_TYPE', 'StorageLensConfiguration/DataExport/S3BucketDestination/Encryption/SSEKMS/KeyId', 'aws-properties-s3-storagelens-ssekms.html'),
}
SOURCES = {rule: [CF + url] for rule, _, url in [*NAMES.values(), *KEYS.values()]}
SOURCES['RDS_PROXY_ENDPOINT_NAME_COLLISION'].append('https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBProxyEndpoint.html')
for rule, _, _ in KEYS.values():
    SOURCES[rule].append(CF + 'aws-resource-kms-key.html')


def identity(ctx, resource, paths):
    parts = []
    for path in paths:
        raw = value(ctx, resource, '/properties/' + path)
        if resource.type == 'AWS::IAM::VirtualMFADevice' and path == 'Path' and raw is ABSENT:
            raw = '/'
        # Deliberately bounded literal subset; this is not a name-format validator.
        if not isinstance(raw, str) or not re.fullmatch(r'[A-Za-z0-9_./+=,@-]{1,512}', raw):
            return None
        if resource.type == 'AWS::RDS::DBClusterParameterGroup':
            raw = raw.lower()  # Explicitly documented storage normalization.
        parts.append(raw)
    return tuple(parts)


@resource_check(*NAMES, *KEYS)
def finite_ledger_checks(design, resource):
    ctx = _Context(design, resource)
    results = []
    if resource.type in NAMES:
        rule, paths, _ = NAMES[resource.type]
        key = identity(ctx, resource, paths)
        known_scope = (re.fullmatch(r'[0-9]{12}', resource.scope.account)
                       and re.fullmatch(r'[a-z]+(?:-[a-z]+)+-[0-9]+', resource.scope.region))
        collisions = [other.id for other in design.resources if known_scope and key is not None
                      and other.id != resource.id and other.type == resource.type and other.scope == resource.scope
                      and identity(ctx, other, paths) == key]
        results.append({**ctx.finding(rule, '/properties/' + (paths[0] if paths else ''),
            'FAIL' if collisions else 'NEEDS_REVIEW',
            'distinct same-scope declarations address the same named or singleton resource: ' + ', '.join(collisions)
            if collisions else 'no proven declaration collision; external inventory, cross-Region account-wide identity, generated names and unresolved values remain unverified'),
            'severity': 'WARNING'})
    if resource.type in KEYS:
        rule, suffix, _ = KEYS[resource.type]
        path = '/properties/' + suffix
        if value(ctx, resource, path) is not ABSENT:
            key = linked(ctx, resource, path, 'AWS::KMS::Key')
            results.append(ctx.finding(rule, path, symmetric_key_verdict(ctx, key),
                'checks the symmetric encryption declaration of an explicitly linked KMS key; external keys, aliases, permissions and effective key state remain unverified'))
    return results
