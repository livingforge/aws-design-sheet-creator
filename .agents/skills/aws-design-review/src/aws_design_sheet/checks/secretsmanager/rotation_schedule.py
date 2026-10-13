"""Conservative evaluation of documented Secrets Manager rotation windows."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

URL = 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_schedule.html'
CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-secretsmanager-rotationschedule-rotationrules.html'
SOURCES = {rule: [URL, CF] for rule in (
    'SECRET_ROTATION_RATE_INTERVAL', 'SECRET_ROTATION_CRON_FIELDS', 'SECRET_ROTATION_WINDOW')}


@resource_check('AWS::SecretsManager::RotationSchedule')
def rotation_schedule(design, resource):
    ctx = _Context(design, resource)
    base = '/properties/RotationRules'
    schedule = value(ctx, resource, base + '/ScheduleExpression')
    duration = value(ctx, resource, base + '/Duration')
    if schedule is ABSENT and duration is ABSENT:
        return []
    rate = re.fullmatch(r'rate\(\s*(\d{1,6})\s+(hours?|days?)\s*\)', schedule) if isinstance(schedule, str) else None
    cron = re.fullmatch(r'cron\(([^{}\n]+)\)', schedule) if isinstance(schedule, str) else None
    results, limit, window_pending = [], None, True
    if rate:
        amount = int(rate[1])
        hourly = rate[2].startswith('hour')
        hours = amount if hourly else amount * 24
        verdict = 'PASS' if 4 <= hours <= 999 * 24 else 'FAIL'
        results.append(ctx.finding('SECRET_ROTATION_RATE_INTERVAL', base + '/ScheduleExpression', verdict,
            'recognized rate intervals must be between four hours and 999 days; other expression forms need review'))
        limit = min(hours, 24)
        # For intervals not dividing a day, the per-day start-time interpretation
        # is not specified precisely enough to certify a multi-hour window.
        window_pending = hourly and (hours <= 0 or 24 % hours != 0)
        if duration is ABSENT:
            duration = '1h' if hourly else '24h'
    elif cron:
        parts = cron[1].split()
        valid = len(parts) == 6 and parts[0] == '0' and parts[5] == '*'
        if valid:
            valid = (parts[2] == '?') != (parts[4] == '?')
        results.append(ctx.finding('SECRET_ROTATION_CRON_FIELDS', base + '/ScheduleExpression',
            'PASS' if valid else 'FAIL',
            'cron requires six fields, minute zero, year *, and one unspecified day field; remaining calendar grammar is not certified'))
        if valid:
            hour = re.fullmatch(r'(\d{1,2})', parts[1])
            increment = re.fullmatch(r'(\d{1,2}|\*)?/(\d{1,2})', parts[1])
            if hour and int(hour[1]) <= 23:
                limit = 24 - int(hour[1])
                window_pending = False
                if duration is ABSENT:
                    duration = f'{limit}h'
            elif increment:
                start = 0 if increment[1] in (None, '*') else int(increment[1])
                step = int(increment[2])
                if start <= 23 and step >= 4:
                    last = start + ((23 - start) // step) * step
                    limit = min(step, 24 - last)
                    window_pending = False
                    if duration is ABSENT:
                        duration = '1h'
    elif schedule is not ABSENT:
        results.append(ctx.finding('SECRET_ROTATION_RATE_INTERVAL', base + '/ScheduleExpression',
            'NEEDS_REVIEW', 'unrecognized or unresolved schedule; no speculative grammar rejection'))
    parsed = re.fullmatch(r'(\d{1,6})h', duration) if isinstance(duration, str) else None
    verdict = 'NEEDS_REVIEW'
    if parsed:
        hours = int(parsed[1])
        if hours < 1 or hours > 24 or limit is not None and hours > limit:
            verdict = 'FAIL'
        elif not window_pending:
            verdict = 'PASS'
    results.append(ctx.finding('SECRET_ROTATION_WINDOW', base + '/Duration', verdict,
        'recognized hour windows must fit the next rotation and UTC day; unsupported durations or schedule forms require review'))
    return results
