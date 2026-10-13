"""Prove duplicate requirement names in explicit queue-limit associations."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'DEADLINE_QUEUE_LIMIT_REQUIREMENT_DUPLICATE':[CF+'aws-resource-deadline-queuelimitassociation.html',CF+'aws-resource-deadline-limit.html',CF+'aws-resource-deadline-queue.html']}


def identity(ctx,resource,key,kind,prefix):
    target=linked(ctx,resource,'/properties/'+key,kind)
    if resolved(target):return ('resource',target.id) if read(ctx,resource,'/properties/'+key) is ABSENT else None
    raw=value(ctx,resource,'/properties/'+key)
    if isinstance(raw,str) and re.fullmatch(prefix+'-[0-9a-f]{32}',raw):return ('literal',raw)
    return None


def association(ctx,r):
    if not resolved(r):return None
    farm=identity(ctx,r,'FarmId','AWS::Deadline::Farm','farm')
    queue=identity(ctx,r,'QueueId','AWS::Deadline::Queue','queue')
    limit=linked(ctx,r,'/properties/LimitId','AWS::Deadline::Limit')
    if farm is None or queue is None or not resolved(limit) or read(ctx,r,'/properties/LimitId') is not ABSENT:return None
    queue_resource=linked(ctx,r,'/properties/QueueId','AWS::Deadline::Queue')
    if queue_resource is not None and identity(ctx,queue_resource,'FarmId','AWS::Deadline::Farm','farm')!=farm:return None
    # A limit belongs to a farm. Contradictory or incomparable identities
    # cannot prove that both associations describe the same remote queue.
    if identity(ctx,limit,'FarmId','AWS::Deadline::Farm','farm')!=farm:return None
    name=value(ctx,limit,'/properties/AmountRequirementName')
    if not literal(name):return None
    return farm,queue,limit.id,name


@resource_check('AWS::Deadline::QueueLimitAssociation')
def evaluate_deadline_limit_names(design,resource):
    if resource.type!='AWS::Deadline::QueueLimitAssociation':return []
    ctx=_Context(design,resource);own=association(ctx,resource);duplicate=False
    if own is not None:
        for other in design.resources:
            if other.id==resource.id or other.type!=resource.type or other.scope!=resource.scope:continue
            candidate=association(ctx,other)
            if candidate is not None and candidate[:2]==own[:2] and candidate[2]!=own[2] and candidate[3]==own[3]:
                duplicate=True
                break
    return [ctx.finding('DEADLINE_QUEUE_LIMIT_REQUIREMENT_DUPLICATE','/properties/LimitId',
        'FAIL' if duplicate else 'NEEDS_REVIEW',
        'Distinct explicitly linked limits with exactly equal AmountRequirementName cannot be associated with the same queue in the same farm and scope. No duplicate found does not certify external uniqueness. Unknown, conditional, cross-scope or incomparable identities remain reviewable.')]
