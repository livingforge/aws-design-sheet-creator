"""EventBridge input-transformer declarations with conservative JSON parsing."""
import json
import re
from ..common.context_values import value
from ..common.field_reads import ABSENT

URL = 'https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_InputTransformer.html'
GUIDE = 'https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-transform-target-input.html'
SOURCES = {rule: [URL, GUIDE] for rule in ('EVENTS_INPUT_PATH_SYNTAX', 'EVENTS_TEMPLATE_PLACEHOLDER_KEYS')}
VARIABLE = re.compile(r'<([A-Za-z0-9_.-]+)>')
PREDEFINED = {'aws.events.rule-arn', 'aws.events.rule-name', 'aws.events.event.ingestion-time',
              'aws.events.event', 'aws.events.event.json'}


def reject_constant(_):
    raise ValueError('non-JSON number')


def object_key_verdict(template, names):
    if not isinstance(template, str) or len(template) > 8192 or '${' in template or '{{' in template:
        return 'NEEDS_REVIEW'
    if not template.lstrip().startswith('{'):
        return 'NOT_APPLICABLE'
    fragments, index, keys, duplicate = [], 0, [], False
    decoder = json.JSONDecoder()
    try:
        while index < len(template):
            if template[index] == '"':
                _, length = decoder.raw_decode(template[index:])
                fragments.append(template[index:index + length])
                index += length
                continue
            variable = VARIABLE.match(template, index)
            if variable:
                fragments.append(json.dumps(variable[0]))
                index = variable.end()
            else:
                fragments.append(template[index])
                index += 1

        def capture(pairs):
            nonlocal duplicate
            keys.extend(key for key, _ in pairs)
            duplicate |= len(pairs) != len({key for key, _ in pairs})
            return dict(pairs)

        body = json.loads(''.join(fragments), object_pairs_hook=capture, parse_constant=reject_constant)
        if not isinstance(body, dict):
            return 'NEEDS_REVIEW'
    except (ValueError, RecursionError):
        return 'NEEDS_REVIEW'
    matches = [match[1] for key in keys for match in VARIABLE.finditer(key)]
    if any(name in PREDEFINED or names is not None and name in names for name in matches):
        return 'FAIL'
    return 'NEEDS_REVIEW' if matches or duplicate or names is None else 'PASS'


def event_input(ctx, resource, target_path):
    base = target_path + '/InputTransformer'
    mapping = value(ctx, resource, base + '/InputPathsMap')
    names = set() if mapping is ABSENT else None
    results = []
    if isinstance(mapping, dict) and not any(key.startswith(('Fn::', '$')) or key == 'Ref' for key in mapping):
        names = set(mapping)
        for key in mapping:
            path = base + '/InputPathsMap/' + key.replace('~', '~0').replace('/', '~1')
            raw = value(ctx, resource, path)
            supported = isinstance(raw, str) and re.fullmatch(r'\$(?:\.(?:[A-Za-z0-9_/-]+|\*))+', raw) is not None
            results.append(ctx.finding('EVENTS_INPUT_PATH_SYNTAX', path,
                'PASS' if supported else 'NEEDS_REVIEW',
                'recognizes documented dot paths only; array/bracket wording conflicts, other syntax and runtime event fields remain unverified'))
    elif mapping is not ABSENT:
        results.append(ctx.finding('EVENTS_INPUT_PATH_SYNTAX', base + '/InputPathsMap', 'NEEDS_REVIEW', 'input paths are unresolved'))
    template = value(ctx, resource, base + '/InputTemplate')
    if template is not ABSENT:
        results.append(ctx.finding('EVENTS_TEMPLATE_PLACEHOLDER_KEYS', base + '/InputTemplate', object_key_verdict(template, names),
            'a known placeholder cannot be an object key in a JSON-object template; unknown variables, unsupported template shapes and runtime substitution remain unverified'))
    return results
