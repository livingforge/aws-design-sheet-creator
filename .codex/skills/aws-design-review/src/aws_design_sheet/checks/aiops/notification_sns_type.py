"""Checks for AWS::AIOps::InvestigationGroup."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'AIOPS_NOTIFICATION_SNS_TYPE': [CF+'aws-properties-aiops-investigationgroup-chatbotnotificationchannel.html'],
}


@resource_check('AWS::AIOps::InvestigationGroup')
def evaluate_aiops_notification_sns_type(design, resource):
    ctx = _Context(design, resource); results = []
    def emit(rule, path, verdict, reason):
        f = ctx.finding(rule, path, verdict, reason); f['source_checked_at'] = '2026-10-04'; results.append(f)
    if resource.type == 'AWS::AIOps::InvestigationGroup':
        for path in expand(ctx, resource, '/properties/ChatbotNotificationChannels/*/SNSTopicArn'):
            raw = value(ctx, resource, path)
            match = re.fullmatch(r'arn:(aws(?:-[a-z]+)*):([a-z0-9-]+):([a-z0-9-]*):([0-9]{12}):([^\s]+)', raw) if literal(raw) else None
            verdict = 'NEEDS_REVIEW' if not match else 'PASS' if match[2] == 'sns' else 'FAIL'
            emit('AIOPS_NOTIFICATION_SNS_TYPE', path, verdict, 'recognized ARN service must be SNS; topic grammar, partition/Region/account permissions and chat configuration targets remain open')
    return results
