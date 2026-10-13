"""CloudFormation's documented canary/linear deployment-time estimate."""
from decimal import Decimal, InvalidOperation
from ..common.context_values import value
from ..common.field_reads import ABSENT

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {'ECS_SERVICE_DEPLOYMENT_TIME': [CF + 'aws-properties-ecs-service-' + name + '.html'
    for name in ('deploymentconfiguration', 'canaryconfiguration', 'linearconfiguration')]}


def deployment_time(ctx, resource):
    base = '/properties/DeploymentConfiguration'
    strategy = value(ctx, resource, base + '/Strategy')
    if strategy not in ('CANARY', 'LINEAR'):
        return []
    bake = value(ctx, resource, base + '/BakeTimeInMinutes')
    if bake is ABSENT:
        bake = 15
    if strategy == 'CANARY':
        wait = value(ctx, resource, base + '/CanaryConfiguration/CanaryBakeTimeInMinutes')
        if wait is ABSENT:
            wait = 10
        steps = 1
    else:
        wait = value(ctx, resource, base + '/LinearConfiguration/StepBakeTimeInMinutes')
        percent = value(ctx, resource, base + '/LinearConfiguration/StepPercent')
        if wait is ABSENT:
            wait = 6
        if percent is ABSENT:
            percent = 10
        steps = None
        if type(percent) in (int, float):
            try:
                decimal = Decimal(str(percent))
                if decimal.is_finite() and 3 <= decimal <= 100 and decimal * 10 == (decimal * 10).to_integral_value():
                    tenths = int(decimal * 10)
                    # ceil(100 / StepPercent) - 1 excludes the final 100% shift.
                    steps = (1000 + tenths - 1) // tenths - 1
            except InvalidOperation:
                pass
    total = bake + wait * steps if type(bake) is int and bake >= 0 and type(wait) is int and wait >= 0 and steps is not None else None
    verdict = 'NEEDS_REVIEW' if total is None else 'FAIL' if total > 1980 else 'PASS'
    return [ctx.finding('ECS_SERVICE_DEPLOYMENT_TIME', base, verdict,
        'CloudFormation rejects estimated canary/linear bake time over 1980 minutes; final linear shift adds no step bake, and backend work can still exceed the operation timeout')]
