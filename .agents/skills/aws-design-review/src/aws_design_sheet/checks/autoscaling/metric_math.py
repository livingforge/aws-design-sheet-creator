"""References in a bounded arithmetic subset of Auto Scaling metric math."""
import re
from ..registry import resource_check
from .math_types import BAD, infer_type, parse_math, references
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

SOURCES = {'AUTOSCALING_MATH_REFERENCES': [
    'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html',
    'https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-target-tracking-metric-math.html',
    'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-scalingpolicy-metricdataquery.html']}
SOURCES['AUTOSCALING_MATH_ARGUMENT_TYPES'] = SOURCES['AUTOSCALING_MATH_REFERENCES']
IDENTIFIER = re.compile(r'[a-z][A-Za-z0-9_]*')
TOKEN = re.compile(r'\s*([a-z][A-Za-z0-9_]*|[0-9]+(?:\.[0-9]+)?|[()+*/^\-])')


def arithmetic_references(raw):
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 4096:
        return None
    position, depth, operand = 0, 0, True
    refs = set()
    while position < len(raw.rstrip()):
        token = TOKEN.match(raw, position)
        if not token:
            return None
        position = token.end()
        item = token[1]
        if item == '(':
            if not operand:
                return None
            depth += 1
        elif item == ')':
            if operand or not depth:
                return None
            depth -= 1
        elif item in ('+', '-', '*', '/', '^'):
            if operand and item != '-':
                return None
            operand = True
        else:
            if not operand:
                return None
            if IDENTIFIER.fullmatch(item):
                refs.add(item)
            operand = False
    return refs if not operand and depth == 0 else None


@resource_check('AWS::AutoScaling::ScalingPolicy')
def math_references(design, resource):
    ctx = _Context(design, resource)
    paths = ['/properties/TargetTrackingConfiguration/CustomizedMetricSpecification/Metrics']
    root = '/properties/PredictiveScalingConfiguration/MetricSpecifications'
    specs = value(ctx, resource, root)
    if isinstance(specs, list):
        paths.extend(root + f'/{i}/{kind}/MetricDataQueries' for i in range(len(specs)) for kind in (
            'CustomizedScalingMetricSpecification', 'CustomizedLoadMetricSpecification', 'CustomizedCapacityMetricSpecification'))
    elif specs is not ABSENT:
        paths.append(root)
    results = []
    for path in paths:
        queries = value(ctx, resource, path)
        if queries is ABSENT:
            continue
        if not isinstance(queries, list):
            results.append(ctx.finding('AUTOSCALING_MATH_REFERENCES', path, 'NEEDS_REVIEW', 'query set is unresolved'))
            continue
        ids = [value(ctx, resource, path + f'/{i}/Id') for i in range(len(queries))]
        valid_ids = [item for item in ids if isinstance(item, str) and IDENTIFIER.fullmatch(item)]
        complete_ids = len(valid_ids) == len(ids) == len(set(valid_ids))
        expressions = [value(ctx, resource, path + f'/{i}/Expression') for i in range(len(queries))]
        parsed = [parse_math(expression) for expression in expressions]
        metric_ids = {identifier for i, identifier in enumerate(ids) if isinstance(identifier, str)
                      and expressions[i] is ABSENT and isinstance(value(ctx, resource, path + f'/{i}/MetricStat'), dict)}
        trees = {identifier: tree for identifier, tree in zip(ids, parsed) if isinstance(identifier, str)}
        active_types = set()
        type_cache = {}

        def resolve_type(identifier):
            if not complete_ids or identifier in active_types or len(active_types) > 64:
                return None
            if identifier in metric_ids:
                return 'TS'
            if identifier in type_cache:
                return type_cache[identifier]
            active_types.add(identifier)
            try:
                kind = infer_type(trees.get(identifier), resolve_type, metric_ids)
                type_cache[identifier] = kind
                return kind
            except RecursionError:
                return None
            finally:
                active_types.remove(identifier)
        graph = {}
        for i, (identifier, expression) in enumerate(zip(ids, expressions)):
            if isinstance(identifier, str):
                metric = value(ctx, resource, path + f'/{i}/MetricStat')
                graph[identifier] = (set() if isinstance(metric, dict) else None) if expression is ABSENT else references(parsed[i], metric_ids)
        for i, expression in enumerate(expressions):
            if expression is ABSENT:
                continue
            refs = references(parsed[i], metric_ids)
            verdict = 'NEEDS_REVIEW'
            if refs is not None and complete_ids:
                if refs - set(valid_ids):
                    verdict = 'FAIL'
                else:
                    verdict = 'PASS'
                    pending, visited, active = [(name, False) for name in refs], set(), {ids[i]}
                    while pending:
                        name, exiting = pending.pop()
                        if exiting:
                            active.remove(name)
                            visited.add(name)
                            continue
                        if name in active:
                            verdict = 'NEEDS_REVIEW'
                            break
                        if name in visited:
                            continue
                        dependencies = graph.get(name)
                        if dependencies is None or dependencies - set(valid_ids):
                            verdict = 'NEEDS_REVIEW'
                            break
                        active.add(name)
                        pending.append((name, True))
                        pending.extend((child, False) for child in dependencies)
            results.append(ctx.finding('AUTOSCALING_MATH_REFERENCES', path + f'/{i}/Expression', verdict,
                'checks IDs within this query set for supported arithmetic and allowlisted function expressions; cycles, other functions, unknown dependencies and runtime data remain unverified'))
            kind = resolve_type(ids[i]) if isinstance(ids[i], str) else None
            returns = value(ctx, resource, path + f'/{i}/ReturnData')
            type_verdict = ('FAIL' if kind == BAD or returns is True and kind in ('S', 'TS[]', 'String', 'S[]')
                            else 'PASS' if kind == 'TS' else 'NEEDS_REVIEW')
            results.append(ctx.finding('AUTOSCALING_MATH_ARGUMENT_TYPES', path + f'/{i}/Expression', type_verdict,
                'checks documented argument types of allowlisted functions; returned scaling metrics must be a single time series, while unsupported forms, non-returned scalar/array queries and runtime data remain unverified'))
    return results
