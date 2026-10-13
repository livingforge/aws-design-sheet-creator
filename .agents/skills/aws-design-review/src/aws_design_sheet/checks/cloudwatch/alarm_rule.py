"""Bounded parsing of documented composite-alarm expressions and local links."""
import re
from dataclasses import dataclass
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

URL = 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutCompositeAlarm.html'
SOURCES = {name: [URL] for name in (
    'CLOUDWATCH_ALARM_RULE_DECLARATIONS', 'CLOUDWATCH_ALARM_RULE_CHILD_COUNT',
    'CLOUDWATCH_ALARM_RULE_CYCLE',
)}
PATH = '/properties/AlarmRule'
KINDS = {'AWS::CloudWatch::Alarm', 'AWS::CloudWatch::CompositeAlarm'}
TOKEN = re.compile(r'\s*(?:(ALARM|OK|INSUFFICIENT_DATA)\s*\(\s*(?:"([^"\\\r\n]+)"|([A-Za-z0-9_.:/-]+))\s*\)|(TRUE|FALSE|AND|OR|NOT)\b|([()]))')
ARN = re.compile(r'arn:(aws|aws-cn|aws-us-gov):cloudwatch:([a-z0-9-]+):([0-9]{12}):alarm:(.+)')


@dataclass(frozen=True)
class Expression:
    references: tuple[str, ...]


def parse_expression(raw):
    """Recognize a safe subset; unsupported/invalid syntax is never certified."""
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 10240 or '${' in raw or '{{' in raw:
        return None
    position, depth, expect_operand = 0, 0, True
    refs = []
    while position < len(raw.rstrip()):
        token = TOKEN.match(raw, position)
        if token is None:
            return None
        position = token.end()
        function, quoted, bare, word, parenthesis = token.groups()
        if function or word in ('TRUE', 'FALSE'):
            if not expect_operand:
                return None
            if function:
                refs.append(quoted if quoted is not None else bare)
            expect_operand = False
        elif word == 'NOT':
            if not expect_operand:
                return None
        elif word in ('AND', 'OR'):
            if expect_operand:
                return None
            expect_operand = True
        elif parenthesis == '(':
            if not expect_operand:
                return None
            depth += 1
        elif parenthesis == ')':
            if expect_operand or depth == 0:
                return None
            depth -= 1
    return Expression(tuple(refs)) if not expect_operand and depth == 0 else None


def known_scope(resource):
    return (re.fullmatch(r'[0-9]{12}', resource.scope.account) is not None
            and re.fullmatch(r'[a-z]+(?:-[a-z]+)+-[0-9]+', resource.scope.region) is not None)


def reference_name(resource, raw):
    if not raw.startswith('arn:'):
        return raw
    match = ARN.fullmatch(raw)
    if not match:
        return None
    partition, region, account, name = match.groups()
    expected = 'aws-cn' if resource.scope.region.startswith('cn-') else 'aws-us-gov' if resource.scope.region.startswith('us-gov-') else 'aws'
    return name if known_scope(resource) and (partition, region, account) == (expected, resource.scope.region, resource.scope.account) else None


@resource_check('AWS::CloudWatch::CompositeAlarm')
def alarm_rule(design, resource):
    ctx = _Context(design, resource)
    raw = value(ctx, resource, PATH)
    if raw is ABSENT:
        return []
    expression = parse_expression(raw)
    if expression is None:
        return [ctx.finding(rule, PATH, 'NEEDS_REVIEW',
            'expression is unresolved or outside the bounded supported grammar; no dependency or validity claim is made') for rule in SOURCES]

    # Name/ARN aliases must not be double-counted. Without scope, use only a
    # conservative lower bound from either names or canonical literal ARNs.
    names = {name for ref in expression.references if (name := reference_name(resource, ref)) is not None}
    unknown_refs = {ref for ref in expression.references if reference_name(resource, ref) is None}
    literal_names = {ref for ref in expression.references if not ref.startswith('arn:')}
    literal_arns = {ref for ref in expression.references if ARN.fullmatch(ref)}
    lower_bound = max(len(names), len(literal_names), len(literal_arns))
    count = 'FAIL' if lower_bound > 100 else 'NEEDS_REVIEW' if unknown_refs else 'PASS'
    results = [ctx.finding('CLOUDWATCH_ALARM_RULE_CHILD_COUNT', PATH, count,
        'counts distinct literal child identities, normalizing local ARN/name aliases; unresolved identities and element-count semantics remain separate')]

    pool = [other for other in design.resources if other.type in KINDS and other.scope == resource.scope]
    index = {}
    if known_scope(resource):
        for other in pool:
            name = value(ctx, other, '/properties/AlarmName')
            if isinstance(name, str) and name and '${' not in name and '{{' not in name:
                index.setdefault(name, []).append(other)

    def resolve(current, parsed):
        targets, complete = [], True
        for ref in set(parsed.references):
            name = reference_name(current, ref)
            candidates = index.get(name, [])
            if len(candidates) != 1:
                complete = False
            else:
                targets.append(candidates[0])
        return targets, complete

    targets, complete = resolve(resource, expression)
    results.append(ctx.finding('CLOUDWATCH_ALARM_RULE_DECLARATIONS', PATH,
        'PASS' if complete else 'NEEDS_REVIEW',
        'checks unique explicit alarm names in the same known scope; missing declarations do not prove that external alarms do not exist'))

    # Iterative traversal avoids recursion and reports only cycles involving this
    # resource; unsupported descendants prevent a no-cycle certification.
    pending, visited, cycle = list(targets), set(), False
    while pending:
        other = pending.pop()
        if other.id == resource.id:
            cycle = True
            break
        if other.id in visited or other.type != 'AWS::CloudWatch::CompositeAlarm':
            continue
        visited.add(other.id)
        parsed = parse_expression(value(ctx, other, PATH))
        if parsed is None:
            complete = False
            continue
        children, resolved = resolve(other, parsed)
        complete = complete and resolved
        pending.extend(children)
    finding = ctx.finding('CLOUDWATCH_ALARM_RULE_CYCLE', PATH,
        'FAIL' if cycle else 'PASS' if complete else 'NEEDS_REVIEW',
        'declared cycles can be created but stop evaluation and block deletion; this warning checks cycles through this alarm only, not deployment or runtime state')
    finding['severity'] = 'WARNING'
    results.append(finding)
    return results
