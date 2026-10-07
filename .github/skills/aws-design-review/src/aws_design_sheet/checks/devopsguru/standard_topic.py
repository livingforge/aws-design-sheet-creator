"""Checks for AWS::DevOpsGuru::NotificationChannel."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DEVOPSGURU_STANDARD_TOPIC': [CF+'aws-properties-devopsguru-notificationchannel-snschannelconfig.html', CF+'aws-resource-sns-topic.html'],
}


@resource_check('AWS::DevOpsGuru::NotificationChannel')
def evaluate_devopsguru_standard_topic(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    if resource.type == 'AWS::DevOpsGuru::NotificationChannel':
        p = '/properties/Config/Sns/TopicArn'
        raw = get(p)
        if raw is not ABSENT:
            topic = linked(ctx,resource,p,'AWS::SNS::Topic')
            fifo = value(ctx,topic,'/properties/FifoTopic') if topic else UNKNOWN
            match = re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:sns:[a-z0-9-]+:[0-9]{12}:([A-Za-z0-9_-]+(?:\.fifo)?)',raw) if literal(raw) else None
            verdict = 'FAIL' if fifo is True else 'PASS' if fifo is False else 'FAIL' if match and match[1].endswith('.fifo') else 'PASS' if match else 'NEEDS_REVIEW'
            emit('DEVOPSGURU_STANDARD_TOPIC', p, verdict, 'standard topic identity from explicit FIFO flag or recognized SNS ARN; omitted flags, topic existence, cross-account and KMS permissions remain separate')
    return results
