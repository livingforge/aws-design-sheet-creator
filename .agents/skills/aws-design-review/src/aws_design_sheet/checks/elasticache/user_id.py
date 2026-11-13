"""The ElastiCache user ID 'default' is taken by the built-in user.

Every account and Region already has ElastiCache's built-in user with the ID 'default', so
CloudFormation refuses an AWS::ElastiCache::User declaring it ("Resource of type
'AWS::ElastiCache::User' with identifier 'default' already exists"); cfn-lint 1.57.2 does
not report it. A user group links the built-in user by that ID instead of declaring it.
"""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'ELASTICACHE_USER_ID_DEFAULT_RESERVED': [
        CF + 'aws-resource-elasticache-user.html',
        'https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/Clusters.RBAC.html'],
}
RULE = 'ELASTICACHE_USER_ID_DEFAULT_RESERVED'
PATH = '/properties/UserId'


@resource_check('AWS::ElastiCache::User')
def evaluate_elasticache_user_id_default(design, resource):
    ctx = _Context(design, resource)
    user_id = value(ctx, resource, PATH)
    if user_id is ABSENT:
        return []
    if not literal(user_id):
        return [ctx.finding(RULE, PATH, 'NEEDS_REVIEW', 'UserId is unresolved')]
    if user_id == 'default':
        return [ctx.finding(RULE, PATH, 'FAIL',
                            "UserId 'default' is the built-in user's ID; link that user from the user group instead")]
    if user_id.lower() == 'default':
        return [ctx.finding(RULE, PATH, 'NEEDS_REVIEW',
                            "UserId differs from the built-in 'default' only in case; whether IDs compare case-insensitively is not documented")]
    return [ctx.finding(RULE, PATH, 'PASS', "UserId is not the built-in user's 'default'")]
