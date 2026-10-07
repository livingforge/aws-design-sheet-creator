"""A lower bound on user tags explicitly declared on a secret."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

SOURCES={'SECRET_DECLARED_TAG_LIMIT':[
    'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-secretsmanager-secret.html']}


@resource_check('AWS::SecretsManager::Secret')
def secret_tags(design,resource):
    ctx=_Context(design,resource)
    path='/properties/Tags'
    tags=value(ctx,resource,path)
    if tags is ABSENT:return []
    keys=set()
    for i in range(len(tags) if isinstance(tags,list) else 0):
        key=value(ctx,resource,path+f'/{i}/Key')
        if isinstance(key,str) and key and not key.startswith('aws:') and not any(token in key for token in ('${','{{')):
            keys.add(key)
    return [ctx.finding('SECRET_DECLARED_TAG_LIMIT',path,'FAIL' if len(keys)>50 else 'NEEDS_REVIEW',
        'more than 50 distinct declared non-aws: tag keys exceeds the limit; stack tags, unresolved keys, duplicate-key handling and conflicting documented string lengths remain unverified')]
