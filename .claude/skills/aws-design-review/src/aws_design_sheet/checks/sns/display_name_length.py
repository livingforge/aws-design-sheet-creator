"""Length of an SNS topic display name.

SNS refuses a display name longer than 100 characters (InvalidParameter); cfn-lint 1.57.2 does
not report it. AWS refused it in aws-emulator-evaluation-suite.
"""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SNS_TOPIC_DISPLAY_NAME_LENGTH': [CF + 'aws-resource-sns-topic.html',
                                      'https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html'],
}


@resource_check('AWS::SNS::Topic')
def evaluate_sns_display_name_length(design, resource):
    ctx = _Context(design, resource)
    name = value(ctx, resource, '/properties/DisplayName')
    if not literal(name):
        return []
    verdict = 'PASS' if len(name) <= 100 else 'FAIL'
    return [ctx.finding('SNS_TOPIC_DISPLAY_NAME_LENGTH', '/properties/DisplayName', verdict,
                        f'the display name has at most 100 characters ({len(name)} given)')]
