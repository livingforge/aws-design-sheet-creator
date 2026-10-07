"""Checks for AWS::DAX::Cluster."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DAX_NOTIFICATION_OWNER': [CF+'aws-resource-dax-cluster.html'],
}


@resource_check('AWS::DAX::Cluster')
def evaluate_dax_notification_owner(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    def enum(rule, p, allowed):
        raw = get(p)
        if raw is not ABSENT:
            emit(rule, p, 'NEEDS_REVIEW' if not (literal(raw) or (resource.type=='AWS::CodePipeline::CustomActionType' and raw=='')) else 'PASS' if raw in allowed else 'FAIL', 'documented explicit value only; applicability and service state remain separate')
    if resource.type == 'AWS::DAX::Cluster':
        p = '/properties/NotificationTopicARN'
        raw = get(p)
        if raw is not ABSENT:
            topic = linked(ctx, resource, p, 'AWS::SNS::Topic')
            match = re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:sns:[a-z0-9-]+:([0-9]{12}):[^:*?]+', raw) if literal(raw) else None
            verdict = 'NEEDS_REVIEW'
            if known_scope(resource):
                if topic:
                    verdict = 'PASS'
                elif match:
                    verdict = 'PASS' if match[1] == resource.scope.account else 'FAIL'
            emit('DAX_NOTIFICATION_OWNER', p, verdict, 'same topic/cluster owner from explicit SNS ARN or unique same-scope link; external topic existence and permissions remain open')
    return results
