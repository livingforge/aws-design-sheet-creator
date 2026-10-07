"""Checks for AWS::CE::AnomalySubscription."""
import json
import re
from decimal import Decimal, InvalidOperation
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CE_THRESHOLD_EXPRESSION_VALUES': [CF+'aws-resource-ce-anomalysubscription.html'],
}


def threshold_verdict(raw):
    """Inspect JSON dimensions without evaluating expressions or substitutions."""
    if not literal(raw) or len(raw) > 100000:
        return 'NEEDS_REVIEW'
    def pairs(items):
        result = {}
        for key, val in items:
            if key in result: raise ValueError('duplicate key')
            result[key] = val
        return result
    try:
        node = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (ValueError, RecursionError):
        return 'NEEDS_REVIEW'
    stack = [node]
    pending = False
    count = dimensions = 0
    while stack:
        node = stack.pop()
        count += 1
        if count > 10000: return 'NEEDS_REVIEW'
        if not isinstance(node, dict) or len(node) != 1:
            pending = True
            continue
        key = next(iter(node))
        child = node[key]
        if key in ('And','Or'):
            if isinstance(child,list) and child: stack.extend(child)
            else: pending = True
        elif key == 'Dimensions':
            dimensions += 1
            if not isinstance(child,dict) or set(child)-{'Key','MatchOptions','Values'}:
                pending = True
                continue
            if child.get('Key') not in ('ANOMALY_TOTAL_IMPACT_ABSOLUTE','ANOMALY_TOTAL_IMPACT_PERCENTAGE'):
                pending = True
                continue
            options = child.get('MatchOptions')
            if isinstance(options,list) and all(literal(x) for x in options):
                if 'GREATER_THAN_OR_EQUAL' not in options: return 'FAIL'
                if options != ['GREATER_THAN_OR_EQUAL']: pending = True
            elif options is None: return 'FAIL'
            else: pending = True
            values = child.get('Values')
            if not isinstance(values,list) or not values:
                pending = True
                continue
            for val in values:
                if not literal(val):
                    pending = True
                    continue
                # Bound decimal parsing and hold alternate lexical representations.
                if len(val) > 1000 or not re.fullmatch(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]{1,6})?',val):
                    pending = True
                    continue
                try: number = Decimal(val)
                except InvalidOperation:
                    pending = True
                    continue
                if not 0 <= number <= Decimal('10000000000'): return 'FAIL'
        else: pending = True
    return 'NEEDS_REVIEW' if pending or not dimensions else 'PASS'


@resource_check('AWS::CE::AnomalySubscription')
def evaluate_ce_threshold_expression_values(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(path): return value(ctx, resource, path)
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::CE::AnomalySubscription':
        path = '/properties/ThresholdExpression'
        raw = get(path)
        if raw is not ABSENT:
            emit('CE_THRESHOLD_EXPRESSION_VALUES',path,threshold_verdict(raw),'checks literal JSON And/Or dimension match option and decimal-string 0..10000000000 bounds; duplicate keys, unsupported structure, alternate number spellings and parser limits held; does not execute expressions')
    return results
