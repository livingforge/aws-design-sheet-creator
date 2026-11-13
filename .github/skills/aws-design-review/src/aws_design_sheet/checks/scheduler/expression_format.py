"""Form of an EventBridge Scheduler schedule expression.

Scheduler refuses an expression that is not rate(value unit), cron(six fields) or
at(yyyy-mm-ddThh:mm:ss) (ValidationException); cfn-lint 1.57.2 does not check the form. AWS
refused "rate(five minutes)" in aws-emulator-evaluation-suite. Only the outer form is checked:
the cron fields' values and the time of an at() expression are not.
"""
import re

from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SCHEDULER_EXPRESSION_FORMAT': [CF + 'aws-resource-scheduler-schedule.html',
                                    'https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html'],
}
FORMS = (r'rate\([1-9][0-9]* (minute|minutes|hour|hours|day|days)\)',
         r'cron\(\S+( \S+){5}\)',
         r'at\([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\)')


@resource_check('AWS::Scheduler::Schedule')
def evaluate_scheduler_expression_format(design, resource):
    ctx = _Context(design, resource)
    expression = value(ctx, resource, '/properties/ScheduleExpression')
    if not literal(expression):
        return []
    verdict = 'PASS' if any(re.fullmatch(form, expression) for form in FORMS) else 'FAIL'
    return [ctx.finding('SCHEDULER_EXPRESSION_FORMAT', '/properties/ScheduleExpression', verdict,
                        'the expression is rate(value unit), cron(six fields) or at(yyyy-mm-ddThh:mm:ss)')]
