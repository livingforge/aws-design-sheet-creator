"""State Manager rate intervals and explicit schedule-offset prerequisites."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT

URL = 'https://docs.aws.amazon.com/systems-manager/latest/userguide/reference-cron-and-rate-expressions.html'
SOURCES = {rule: [URL] for rule in ('SSM_ASSOCIATION_RATE_INTERVAL', 'SSM_ASSOCIATION_OFFSET_CRON')}
SOURCES['SSM_WINDOW_OFFSET_CRON'] = [URL]
SOURCES['SSM_WINDOW_TASK_TARGET_TYPE'] = ['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ssm-maintenancewindowtask.html']


@resource_check('AWS::SSM::MaintenanceWindowTask')
def window_task_target(design, resource):
    ctx = _Context(design, resource)
    kind = value(ctx, resource, '/properties/TaskType')
    expected = {'RUN_COMMAND': 'AWS::SSM::Document', 'AUTOMATION': 'AWS::SSM::Document',
                'LAMBDA': 'AWS::Lambda::Function', 'STEP_FUNCTIONS': 'AWS::StepFunctions::StateMachine'}
    verdict = 'NEEDS_REVIEW'
    if isinstance(kind, str) and kind in expected:
        for target_type in set(expected.values()):
            if linked(ctx, resource, '/properties/TaskArn', target_type):
                verdict = 'PASS' if target_type == expected[kind] else 'FAIL'
                break
    return [ctx.finding('SSM_WINDOW_TASK_TARGET_TYPE', '/properties/TaskArn', verdict,
        'checks explicit same-scope task-target resource type only; literal names/ARNs, document subtype, permissions and runtime availability require separate review')]


@resource_check('AWS::SSM::MaintenanceWindow')
def window_schedule(design, resource):
    ctx = _Context(design, resource)
    offset = value(ctx, resource, '/properties/ScheduleOffset')
    if offset is ABSENT:
        return []
    raw = value(ctx, resource, '/properties/Schedule')
    verdict = 'NEEDS_REVIEW'
    if type(offset) is int and offset >= 0:
        if raw is ABSENT or isinstance(raw, str) and re.fullmatch(r'(rate|at)\([^{}]+\)', raw):
            verdict = 'FAIL'
        elif isinstance(raw, str) and re.fullmatch(r'cron\([^{}]+\)', raw):
            verdict = 'PASS'
    return [ctx.finding('SSM_WINDOW_OFFSET_CRON', '/properties/ScheduleOffset', verdict,
        'an explicit maintenance-window offset requires a cron schedule; cron grammar, offset bounds and execution dates are checked separately')]


@resource_check('AWS::SSM::Association')
def association_schedule(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/ScheduleExpression'
    raw = value(ctx, resource, path)
    offset = value(ctx, resource, '/properties/ScheduleOffset')
    results = []
    rate = re.fullmatch(r'rate\(\s*(-?[0-9]{1,12})\s+(minutes?|hours?|days?)\s*\)', raw) if isinstance(raw, str) else None
    if raw is not ABSENT:
        if rate:
            amount, unit = int(rate[1]), rate[2]
            minutes = amount * (1440 if unit.startswith('day') else 60 if unit.startswith('hour') else 1)
            valid = 30 <= minutes < 31 * 1440 and unit.endswith('s') == (amount != 1)
            verdict = 'PASS' if valid else 'FAIL'
        elif isinstance(raw, str) and re.fullmatch(r'(cron|at)\([^{}]+\)', raw):
            verdict = 'NOT_APPLICABLE'
        else:
            verdict = 'NEEDS_REVIEW'
        results.append(ctx.finding('SSM_ASSOCIATION_RATE_INTERVAL', path, verdict,
            'recognized integer rate intervals must be at least 30 minutes and less than 31 days, using singular units only for one; cron/at grammar remains separate'))
    if offset is not ABSENT:
        apply = value(ctx, resource, '/properties/ApplyOnlyAtCronInterval')
        known_offset = type(offset) is int and offset >= 0
        cron = isinstance(raw, str) and re.fullmatch(r'cron\([^{}]+\)', raw) is not None
        other = isinstance(raw, str) and re.fullmatch(r'(rate|at)\([^{}]+\)', raw) is not None
        verdict = 'NEEDS_REVIEW'
        if known_offset:
            if other or raw is ABSENT or apply is False or apply is ABSENT:
                verdict = 'FAIL'
            elif cron and apply is True:
                verdict = 'PASS'
        results.append(ctx.finding('SSM_ASSOCIATION_OFFSET_CRON', '/properties/ScheduleOffset', verdict,
            'an explicit offset requires a cron schedule and ApplyOnlyAtCronInterval=true; this prerequisite check does not certify cron grammar or execution dates'))
    return results
