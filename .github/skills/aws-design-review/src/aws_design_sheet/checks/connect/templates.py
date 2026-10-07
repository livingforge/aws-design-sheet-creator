"""Checks for these resource types:

- AWS::Connect::InstanceStorageConfig
- AWS::Connect::QuickConnect
- AWS::Connect::TestCase
- AWS::Connect::User
"""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.json_verdict import json_verdict
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CONNECT_STORAGE_KEY_SPEC': [CF+'aws-properties-connect-instancestorageconfig-encryptionconfig.html'],
    'CONNECT_QUICK_FLOW_TYPE': [CF+'aws-properties-connect-quickconnect-queuequickconnectconfig.html', CF+'aws-properties-connect-quickconnect-userquickconnectconfig.html', CF+'aws-resource-connect-contactflow.html'],
    'CONNECT_TEST_INITIALIZATION_JSON': [CF+'aws-resource-connect-testcase.html'],
    'CONNECT_USER_IDENTITY_FIELDS': [CF+'aws-properties-connect-user-useridentityinfo.html', CF+'aws-resource-connect-instance.html'],
}
FLOW_TYPES = ('CONTACT_FLOW','CUSTOMER_QUEUE','CUSTOMER_HOLD','CUSTOMER_WHISPER','AGENT_HOLD','AGENT_WHISPER','OUTBOUND_WHISPER','AGENT_TRANSFER','QUEUE_TRANSFER','CAMPAIGN')


@resource_check(
    'AWS::Connect::InstanceStorageConfig',
    'AWS::Connect::QuickConnect',
    'AWS::Connect::TestCase',
    'AWS::Connect::User',
)
def evaluate_connect_templates(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    if resource.type == 'AWS::Connect::InstanceStorageConfig':
        for branch in ('S3Config', 'KinesisVideoStreamConfig'):
            p = '/properties/'+branch+'/EncryptionConfig/KeyId'
            if get(p) is ABSENT:
                continue
            key = linked(ctx, resource, p, 'AWS::KMS::Key')
            spec = value(ctx, key, '/properties/KeySpec') if key else UNKNOWN
            verdict = 'PASS' if spec == 'SYMMETRIC_DEFAULT' else 'FAIL' if literal(spec) else 'NEEDS_REVIEW'
            emit('CONNECT_STORAGE_KEY_SPEC', p, verdict, 'checks explicit KeySpec of uniquely linked same-scope key; omitted defaults, aliases, external keys and permissions remain held')
    if resource.type == 'AWS::Connect::QuickConnect':
        for branch, expected in (('QueueConfig','QUEUE_TRANSFER'), ('UserConfig','AGENT_TRANSFER')):
            p = '/properties/QuickConnectConfig/'+branch+'/ContactFlowArn'
            if get(p) is ABSENT:
                continue
            flow = linked(ctx, resource, p, 'AWS::Connect::ContactFlow')
            kind = value(ctx, flow, '/properties/Type') if flow else UNKNOWN
            verdict = 'NEEDS_REVIEW' if kind not in FLOW_TYPES else 'PASS' if kind == expected else 'FAIL'
            emit('CONNECT_QUICK_FLOW_TYPE', p, verdict, 'checks explicit type of uniquely linked flow; instance ownership, version and external flow state remain separate')
    if resource.type == 'AWS::Connect::TestCase':
        p = '/properties/InitializationData'
        if get(p) is not ABSENT:
            emit('CONNECT_TEST_INITIALIZATION_JSON', p, json_verdict(get(p)), 'JSON syntax only; unresolved substitutions, excessive size/depth and initialization semantics remain separate')
    if resource.type == 'AWS::Connect::User':
        instance = linked(ctx, resource, '/properties/InstanceArn', 'AWS::Connect::Instance')
        kind = value(ctx, instance, '/properties/IdentityManagementType') if instance else UNKNOWN
        for field in ('FirstName', 'LastName', 'Email'):
            p = '/properties/IdentityInfo/'+field
            raw = get(p)
            if kind not in ('CONNECT_MANAGED', 'SAML', 'EXISTING_DIRECTORY'):
                verdict = 'NEEDS_REVIEW'
            elif field == 'Email':
                if kind != 'SAML':
                    continue
                verdict = 'PASS' if raw is ABSENT else 'FAIL' if isinstance(raw, str) and literal(raw) else 'NEEDS_REVIEW'
            elif kind in ('CONNECT_MANAGED', 'SAML'):
                verdict = 'FAIL' if raw is ABSENT else 'PASS' if literal(raw) else 'NEEDS_REVIEW'
            else:
                continue
            emit('CONNECT_USER_IDENTITY_FIELDS', p, verdict, 'explicit linked instance controls required first/last names and forbidden SAML Email; unresolved values, normalization and directory update behavior remain separate')
    return results
