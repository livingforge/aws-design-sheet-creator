"""Checks for AWS::CodeStarNotifications::NotificationRule."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODESTAR_NOTIFICATION_TARGET_TYPE': [CF+'aws-properties-codestarnotifications-notificationrule-target.html'],
}


@resource_check('AWS::CodeStarNotifications::NotificationRule')
def evaluate_codestarnotifications_notification_target_type(design, resource):
    ctx = _Context(design, resource)
    results = []

    def get(path):
        return value(ctx, resource, path)

    def emit(rule, path, verdict, reason):
        f = ctx.finding(rule, path, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)

    def enum(rule, path, allowed):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL', 'checks documented literal values; external availability and applicability remain separate')

    if resource.type == 'AWS::CodeStarNotifications::NotificationRule':
        for p in expand(ctx, resource, '/properties/Targets/*/TargetType'):
            enum('CODESTAR_NOTIFICATION_TARGET_TYPE', p, ('SNS', 'AWSChatbotSlack', 'AWSChatbotMicrosoftTeams'))
    return results
