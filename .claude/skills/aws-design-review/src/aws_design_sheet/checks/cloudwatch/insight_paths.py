"""Known Contributor Insights field paths and account wildcard restrictions."""
import json
import re
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

URL = 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContributorInsights-RuleSyntax.html'
SOURCES = {rule: [URL] for rule in (
    'CLOUDWATCH_INSIGHT_FIELD_PATHS', 'CLOUDWATCH_INSIGHT_CLF_FIELDS',
    'CLOUDWATCH_INSIGHT_ARN_ACCOUNT_WILDCARD',
)}
PATH = '/properties/RuleBody'
JSON_PATH = re.compile(r'\$(?:\.[A-Za-z][A-Za-z0-9]*(?:\[(?:0|[1-9][0-9]*)\])?)+')


def unique_object(pairs):
    result = {}
    for key, item in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = item
    return result


def insight_paths(design, resource):
    ctx = _Context(design, resource)
    raw = value(ctx, resource, PATH)
    if raw is ABSENT:
        return []
    body = None
    if isinstance(raw, str) and '${' not in raw and '{{' not in raw:
        try:
            body = json.loads(raw, object_pairs_hook=unique_object)
        except (ValueError, RecursionError):
            pass
    if not isinstance(body, dict) or body.get('Schema') != {'Name': 'CloudWatchLogRule', 'Version': 1} or type(body['Schema'].get('Version')) is not int:
        return [ctx.finding(rule, PATH, 'NEEDS_REVIEW', 'requires an unambiguous CloudWatchLogRule v1 JSON body') for rule in SOURCES]
    results = []
    fmt = body.get('LogFormat')
    aliases = body.get('Fields', {})
    known_aliases = set()
    if fmt == 'CLF':
        verdict = 'NEEDS_REVIEW'
        if isinstance(aliases, dict):
            valid = all(re.fullmatch(r'[1-9][0-9]*', key) and isinstance(name, str) and name for key, name in aliases.items())
            bad = any(re.fullmatch(r'(?:-[0-9]+|0+)', key) for key in aliases)
            values = [name for name in aliases.values() if isinstance(name, str)]
            if valid and len(values) == len(set(values)):
                known_aliases = set(values)
                verdict = 'PASS'
            elif bad:
                verdict = 'FAIL'
        results.append(ctx.finding('CLOUDWATCH_INSIGHT_CLF_FIELDS', PATH, verdict,
            'CLF columns start at one; checks positive positions and unambiguous aliases, leaving unknown alias syntax under review'))

    contribution = body.get('Contribution')
    paths, complete = [], isinstance(contribution, dict)
    if complete:
        keys = contribution.get('Keys')
        if isinstance(keys, list):
            paths.extend(keys)
        else:
            complete = False
        if 'ValueOf' in contribution:
            paths.append(contribution['ValueOf'])
        filters = contribution.get('Filters', [])
        if isinstance(filters, list):
            for item in filters:
                if isinstance(item, dict) and 'Match' in item:
                    paths.append(item['Match'])
                else:
                    complete = False
        else:
            complete = False
    bad = False
    for item in paths:
        if not isinstance(item, str):
            complete = False
        elif fmt == 'JSON':
            complete = complete and JSON_PATH.fullmatch(item) is not None
        elif fmt == 'CLF':
            bad |= re.fullmatch(r'(?:-[0-9]+|0+)', item) is not None
            complete = complete and (re.fullmatch(r'[1-9][0-9]*', item) is not None or item in known_aliases)
        else:
            complete = False
    results.append(ctx.finding('CLOUDWATCH_INSIGHT_FIELD_PATHS', PATH,
        'FAIL' if bad else 'PASS' if complete and fmt in ('JSON', 'CLF') else 'NEEDS_REVIEW',
        'recognizes documented JSON dot/array paths or positive CLF positions and declared aliases; other field notation and runtime fields remain unverified'))

    if 'LogGroupARNs' in body:
        arns = body['LogGroupARNs']
        complete, bad = isinstance(arns, list), False
        for arn in arns if isinstance(arns, list) else []:
            match = re.fullmatch(r'arn:[a-z0-9-]+:logs:[a-z0-9-]+:([^:]+):.+', arn) if isinstance(arn, str) else None
            if not match:
                complete = False
                continue
            account = match[1]
            if re.fullmatch(r'[0-9*]+', account) and '*' in account and account != '*':
                bad = True
            elif account != '*' and not re.fullmatch(r'[0-9]{12}', account):
                complete = False
        results.append(ctx.finding('CLOUDWATCH_INSIGHT_ARN_ACCOUNT_WILDCARD', PATH,
            'FAIL' if bad else 'PASS' if complete else 'NEEDS_REVIEW',
            'account wildcard must cover the entire account ID; resource wildcard grammar and cross-account observability permissions remain separate'))
    return results
