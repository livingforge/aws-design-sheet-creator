"""Documented DMS endpoint enum membership, with ambiguous spellings held."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {'DMS_ENDPOINT_DOCUMENTED_ENUMS': [CF+'aws-resource-dms-endpoint.html'] + [
    CF+'aws-properties-dms-endpoint-'+name+'settings.html' for name in ('kafka','redis','s3')
] + ['https://docs.aws.amazon.com/dms/latest/APIReference/API_CreateEndpoint.html',
     'https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html']}
ENUMS = {
    'EndpointType': ('source','target'),
    'SslMode': ('none','require','verify-ca','verify-full'),
    'KafkaSettings/SecurityProtocol': ('plaintext','ssl-authentication','ssl-encryption','sasl-ssl'),
    'KafkaSettings/MessageFormat': ('json','json-unformatted'),
    'RedisSettings/AuthType': ('none','auth-role','auth-token'),
    'RedisSettings/SslSecurityProtocol': ('plaintext','ssl-encryption'),
    'S3Settings/EncryptionMode': ('sse-s3','sse-kms'),
    'S3Settings/CompressionType': ('none','gzip'),
    'S3Settings/DataFormat': ('csv','parquet'),
    'S3Settings/CannedAclForObjects': ('none','private','public-read','public-read-write','authenticated-read','aws-exec-read','bucket-owner-read','bucket-owner-full-control'),
    'S3Settings/DatePartitionDelimiter': ('SLASH','UNDERSCORE','DASH','NONE'),
    'S3Settings/DatePartitionSequence': ('YYYYMMDD','YYYYMMDDHH','YYYYMM','MMYYYYDD','DDMMYYYY'),
    'S3Settings/EncodingType': ('plain','plain-dictionary','rle-dictionary'),
    'S3Settings/ParquetVersion': ('parquet-1-0','parquet-2-0'),
}
AMBIGUOUS = {field: tuple(s.upper().replace('-','_') for s in ENUMS[field]) for field in (
    'KafkaSettings/MessageFormat','S3Settings/EncryptionMode','S3Settings/CompressionType',
    'S3Settings/CannedAclForObjects','S3Settings/EncodingType')}
AMBIGUOUS['S3Settings/ParquetVersion'] = ('parquet_1_0','parquet_2_0')


@resource_check('AWS::DMS::Endpoint')
def evaluate_dms_endpoint_enums(design, resource):
    if resource.type != 'AWS::DMS::Endpoint':
        return []
    ctx = _Context(design, resource)
    results = []
    for suffix, allowed in ENUMS.items():
        path = '/properties/'+suffix
        raw = value(ctx, resource, path)
        if raw is ABSENT:
            continue
        verdict = 'NEEDS_REVIEW'
        active = True
        if suffix.startswith('S3Settings/DatePartition'):
            enabled = value(ctx, resource, '/properties/S3Settings/DatePartitionEnabled')
            active = enabled is True
            if enabled is False or enabled is ABSENT:
                verdict = 'NOT_APPLICABLE'
        if suffix in ('S3Settings/EncodingType','S3Settings/ParquetVersion'):
            fmt = value(ctx, resource, '/properties/S3Settings/DataFormat')
            active = fmt == 'parquet'
            if fmt == 'csv':
                verdict = 'NOT_APPLICABLE'
        if active and literal(raw) and raw not in AMBIGUOUS.get(suffix, ()):
            verdict = 'PASS' if raw in allowed else 'FAIL'
        finding = ctx.finding('DMS_ENDPOINT_DOCUMENTED_ENUMS',path,verdict,
            'Documented enum membership only. Conflicting prose spellings, unresolved values and unknown activation remain reviewable. Engine catalogs, endpoint/engine compatibility, extra connection attributes and runtime availability are separate.')
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    return results
