"""Checks for AWS::CloudWatch::Dashboard, AWS::CloudWatch::MetricStream."""
import json
import re
from decimal import Decimal
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.json_constants import reject_constant

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLOUDWATCH_EXTENDED_STATISTIC_KNOWN': [CF + 'aws-resource-cloudwatch-alarm.html',
        'https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html',
        'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Statistics-definitions.html'],
    'CLOUDWATCH_DASHBOARD_STRUCTURE': ['https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Dashboard-Body-Structure.html'],
    'CLOUDWATCH_STREAM_METRIC_NAMES': [CF + 'aws-properties-cloudwatch-metricstream-metricstreamfilter.html'],
    'CLOUDWATCH_STREAM_OTEL_PERCENTILES': [CF + 'aws-resource-cloudwatch-metricstream.html'],
}


def extended_statistic(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/ExtendedStatistic'
    raw = value(ctx, resource, path)
    if raw is ABSENT:
        return []
    verdict = 'NEEDS_REVIEW'
    if isinstance(raw, str) and len(raw) <= 128:
        match = re.fullmatch(r'(p|tm|tc|ts|wm)(-?[0-9]+(?:\.[0-9]+)?)', raw)
        if raw == 'IQM':
            verdict = 'PASS'
        elif match:
            number = Decimal(match[2])
            precision = len(match[2].split('.')[1]) if '.' in match[2] else 0
            verdict = 'FAIL' if not 0 <= number <= 100 else 'PASS'
            if match[1] != 'p' and precision > 10:
                verdict = 'FAIL'
        else:
            verdict = statistic_range(raw)
    return [ctx.finding('CLOUDWATCH_EXTENDED_STATISTIC_KNOWN', path, verdict,
          'checks known percentile, shorthand and range notation only; mixed bounds, ambiguous ordering, unsupported syntax and runtime metric eligibility remain unverified')]


def statistic_range(raw):
    match = re.fullmatch(r'(TM|TC|TS|WM|PR)\(([0-9]+(?:\.[0-9]+)?%?)?:([0-9]+(?:\.[0-9]+)?%?)?\)', raw)
    if not match or not (match[2] or match[3]):
        return 'NEEDS_REVIEW'
    bounds = [item for item in match.groups()[1:] if item is not None]
    percent = [item.endswith('%') for item in bounds]
    if len(set(percent)) > 1 or match[1] == 'PR' and any(percent):
        return 'NEEDS_REVIEW'
    numbers = [Decimal(item.rstrip('%')) for item in bounds]
    if any(percent) and any(number > 100 for number in numbers):
        return 'FAIL'
    if match[1] != 'PR' and any('.' in item and len(item.rstrip('%').split('.')[1]) > 10 for item in bounds):
        return 'FAIL'
    # Ordering and equal-bound service acceptance are not explicitly specified.
    if len(numbers) == 2 and numbers[0] >= numbers[1]:
        return 'NEEDS_REVIEW'
    return 'PASS'


@resource_check('AWS::CloudWatch::Dashboard')
def dashboard(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/DashboardBody'
    raw = value(ctx, resource, path)
    if raw is ABSENT:
        return []
    body, invalid = None, False
    if isinstance(raw, str) and '{{resolve:' not in raw:
        try:
            body = json.loads(raw, parse_constant=reject_constant)
        except (ValueError, RecursionError):
            invalid = True
    bad, pending = invalid, not isinstance(raw, str) or '{{resolve:' in raw
    if not pending and not invalid:
        if not isinstance(body, dict):
            bad = True
        else:
            widgets = body.get('widgets')
            bad |= not isinstance(widgets, list) or len(widgets) > 500
            variables = body.get('variables', [])
            bad |= not isinstance(variables, list) or len(variables) > 25
            bad |= 'end' in body and 'start' not in body
            bad |= body.get('periodOverride', 'auto') not in ('auto', 'inherit')
            for widget in widgets if isinstance(widgets, list) else []:
                if not isinstance(widget, dict):
                    bad = True
                    continue
                if '$state' in widget or '$ref' in widget:
                    pending = True
                    continue
                bad |= widget.get('type') not in ('metric', 'text', 'log', 'alarm', 'explorer', 'chart')
                bad |= not isinstance(widget.get('properties'), dict)
                bad |= ('x' in widget) != ('y' in widget)
                for field, low, high in (('x',0,23),('y',0,None),('width',1,24),('height',1,1000)):
                    if field in widget:
                        v = widget[field]
                        if isinstance(v, dict):
                            pending = True
                        elif type(v) is not int or v < low or high is not None and v > high:
                            bad = True
    return [ctx.finding('CLOUDWATCH_DASHBOARD_STRUCTURE', path,
        'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS',
        'validates dashboard JSON, required widget array, 500/25 widget-variable limits, layout and top-level dependencies; widget-specific semantics are separate')]


@resource_check('AWS::CloudWatch::MetricStream')
def stream_strings(design, resource):
    ctx = _Context(design, resource)
    results = []
    for group in ('IncludeFilters', 'ExcludeFilters'):
        base = '/properties/' + group
        items = value(ctx, resource, base)
        if items is ABSENT:
            continue
        for i in range(len(items) if isinstance(items, list) else 1):
            path = base + f'/{i}/MetricNames'
            names = value(ctx, resource, path)
            if names is ABSENT:
                continue
            pending, bad = not isinstance(names, list), False
            for name in names if isinstance(names, list) else []:
                if not isinstance(name, str) or '{{resolve:' in name:
                    pending = True
                elif not re.fullmatch(r'[\x20-\x7e]+', name) or not name.strip():
                    bad = True
            results.append(ctx.finding('CLOUDWATCH_STREAM_METRIC_NAMES', path,
                'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS',
                'metric filter names must contain printable ASCII and at least one non-whitespace character'))
    output = value(ctx, resource, '/properties/OutputFormat')
    if output == 'json':
        return results
    base = '/properties/StatisticsConfigurations'
    items = value(ctx, resource, base)
    if items is ABSENT:
        return results
    for i in range(len(items) if isinstance(items, list) else 1):
        path = base + f'/{i}/AdditionalStatistics'
        stats = value(ctx, resource, path)
        if stats is ABSENT:
            continue
        pending = output not in ('opentelemetry1.0', 'opentelemetry0.7') or not isinstance(stats, list)
        bad = False
        for statistic in stats if isinstance(stats, list) else []:
            if not isinstance(statistic, str) or '{{resolve:' in statistic:
                pending = True
            elif not re.fullmatch(r'p[0-9]{1,3}(?:\.[0-9]+)?', statistic) or Decimal(statistic[1:]) > 100:
                bad = True
        verdict = ('NEEDS_REVIEW' if output not in ('opentelemetry1.0', 'opentelemetry0.7') else
                   'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS')
        results.append(ctx.finding('CLOUDWATCH_STREAM_OTEL_PERCENTILES', path, verdict,
            'OpenTelemetry streams support percentile additional statistics only'))
    return results
