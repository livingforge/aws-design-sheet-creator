"""Checks for AWS::BedrockAgentCore::Memory, AWS::BedrockAgentCore::OAuth2CredentialProvider."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'AGENTCORE_MEMORY_EXTRACTION_SCOPE': [CF+'aws-properties-bedrockagentcore-memory-metadataschemaentry.html'],
    'AGENTCORE_OAUTH_SIGNING_KEY': [CF+'aws-properties-bedrockagentcore-oauth2credentialprovider-kmskeysourcetype.html', CF+'aws-properties-bedrockagentcore-oauth2credentialprovider-privatekeyjwtconfig.html', 'https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html'],
}
MEMORY_PATHS = tuple('/properties/MemoryStrategies/*/'+suffix+'/MemoryRecordSchema/MetadataSchema/*' for suffix in (
    'SemanticMemoryStrategy', 'SummaryMemoryStrategy', 'UserPreferenceMemoryStrategy',
    'CustomMemoryStrategy', 'CustomMemoryStrategy/Configuration/EpisodicOverride/Reflection',
    'EpisodicMemoryStrategy', 'EpisodicMemoryStrategy/ReflectionConfiguration'))
JWT_BASE = '/properties/Oauth2ProviderConfigInput/CustomOauth2ProviderConfig/PrivateKeyJwtConfig'


@resource_check('AWS::BedrockAgentCore::Memory', 'AWS::BedrockAgentCore::OAuth2CredentialProvider')
def evaluate_bedrockagentcore_agentcore_values(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(path): return value(ctx, resource, path)
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::BedrockAgentCore::Memory':
        for pattern in MEMORY_PATHS:
            for base in expand(ctx,resource,pattern):
                path = base+'/ExtractionConfig'
                raw = get(path)
                if raw is ABSENT: continue
                extraction = get(base+'/ExtractionType')
                verdict = 'PASS' if extraction == 'LLM_INFERRED' and isinstance(raw,dict) else 'NEEDS_REVIEW'
                if extraction == 'STRICTLY_CONSISTENT':
                    # Applicability is stated; service rejection versus ignored is not.
                    verdict = 'NEEDS_REVIEW'
                emit('AGENTCORE_MEMORY_EXTRACTION_SCOPE',path,verdict,
                     'ExtractionConfig applies only to LLM_INFERRED at the same schema entry; other/unknown extraction modes need review, not an assumed rejection; extraction contents separate')
    if resource.type == 'AWS::BedrockAgentCore::OAuth2CredentialProvider':
        path = JWT_BASE+'/PrivateKeySource/KmsKeySource/KmsKeyArn'
        if get(path) is not ABSENT:
            key = linked(ctx,resource,path,'AWS::KMS::Key')
            usage = value(ctx,key,'/properties/KeyUsage') if key else None
            spec = value(ctx,key,'/properties/KeySpec') if key else None
            algorithm = get(JWT_BASE+'/SigningAlgorithm')
            verdict = 'NEEDS_REVIEW'
            if usage in ('ENCRYPT_DECRYPT','GENERATE_VERIFY_MAC','KEY_AGREEMENT') or spec == 'SYMMETRIC_DEFAULT': verdict = 'FAIL'
            elif usage == 'SIGN_VERIFY':
                rsa = ('RSA_2048','RSA_3072','RSA_4096')
                known = rsa+('ECC_NIST_P256','ECC_NIST_P384','ECC_NIST_P521','ECC_SECG_P256K1','HMAC_224','HMAC_256','HMAC_384','HMAC_512')
                if algorithm in ('RS256','PS256','ES256') and spec in known:
                    fits = spec in rsa if algorithm in ('RS256','PS256') else spec == 'ECC_NIST_P256'
                    verdict = 'PASS' if fits else 'FAIL'
            emit('AGENTCORE_OAUTH_SIGNING_KEY',path,verdict,'checks explicit linked KMS key usage and recognized RSA/P256 signing compatibility; absent defaults, aliases, unknown/future key specs and external key policy remain held; output-only configuration ignored')
    return results
