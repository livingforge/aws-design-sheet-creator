"""Processor ordering and counts documented for CloudWatch Logs pipelines."""
from collections import Counter
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN

GUIDE = 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/'
SOURCES = {rule: [GUIDE + 'CloudWatch-Logs-Transformation-Create.html',
    GUIDE + 'CloudWatch-Logs-Transformation-Configurable.html',
    GUIDE + 'CloudWatch-Logs-Transformation-BuiltIn.html'] for rule in (
    'LOGS_PARSER_PIPELINE', 'LOGS_BUILTIN_PARSER_POSITION',
    'LOGS_PROCESSOR_SINGLETONS', 'LOGS_FIRST_JSON_SOURCE')}
BUILTIN = {'ParseCloudfront','ParsePostgres','ParseRoute53','ParseVPC','ParseWAF'}
PARSERS = BUILTIN | {'ParseJSON','ParseKeyValue','Grok','Csv'}
MUTATORS = {'AddKeys','CopyValue','DateTimeConverter','DeleteKeys','ListToMap',
    'LowerCaseString','MoveKeys','RenameKeys','SplitString','SubstituteString',
    'TrimString','TypeConverter','UpperCaseString'}


def transformer_processors(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/TransformerConfig'
    items = value(ctx, resource, path)
    if items is ABSENT:
        return []
    return processor_checks(ctx, path, items, lambda suffix: value(ctx, resource, path + suffix))


def account_transformer_processors(ctx, path, items):
    def read(suffix):
        node = items
        for part in suffix.strip('/').split('/'):
            if isinstance(node, dict):
                if any(key in ('Ref','$ref','$state') or key.startswith('Fn::') for key in node):
                    return UNKNOWN
                node = node.get(part, ABSENT)
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                node = node[int(part)]
            else:
                return UNKNOWN if node is UNKNOWN else ABSENT
        if isinstance(node, dict) and any(key in ('Ref','$ref','$state') or key.startswith('Fn::') for key in node):
            return UNKNOWN
        return node
    return processor_checks(ctx, path, items, read, api_case=True)


def processor_checks(ctx, path, items, read, api_case=False):
    kinds = []
    for i in range(len(items) if isinstance(items, list) else 0):
        entry = read('/' + str(i))
        kind = next(iter(entry)) if isinstance(entry, dict) and len(entry) == 1 else None
        config = read('/' + str(i) + '/' + kind) if isinstance(kind, str) else UNKNOWN
        if isinstance(kind, str) and api_case:
            kind = kind[:1].upper() + kind[1:] if kind[:1].islower() else None
        kinds.append(kind if kind in PARSERS | MUTATORS and isinstance(config, dict) else None)
    pending = not isinstance(items, list) or any(kind is None for kind in kinds)
    count = sum(kind in PARSERS for kind in kinds)
    first = kinds[0] if kinds else None
    bad = count > 5 or bool(kinds) and first in MUTATORS or not pending and count == 0
    verdict = 'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS'
    rows = [ctx.finding('LOGS_PARSER_PIPELINE', path, verdict,
        'a transformer must begin with a parser and contain one to five parsers; ParseToOCSF classification and unknown/future processors remain under review')]
    builtin_positions = [i for i,kind in enumerate(kinds) if kind in BUILTIN]
    bad = len(builtin_positions) > 1 or any(i != 0 and all(k is not None for k in kinds[:i]) for i in builtin_positions)
    rows.append(ctx.finding('LOGS_BUILTIN_PARSER_POSITION', path,
        'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS',
        'at most one documented AWS-vended parser is allowed and it must be first'))
    counts = Counter(kinds)
    bad = any(counts[kind] > 1 for kind in ('Grok','AddKeys','CopyValue'))
    rows.append(ctx.finding('LOGS_PROCESSOR_SINGLETONS', path,
        'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS',
        'grok, addKeys and copyValue may each occur at most once'))
    if first == 'ParseJSON':
        suffix = '/0/parseJSON/source' if api_case else '/0/ParseJSON/Source'
        source_path = path + suffix
        source = read(suffix)
        verdict = 'PASS' if source is ABSENT or source == '@message' else 'FAIL' if isinstance(source, str) and '{' not in source else 'NEEDS_REVIEW'
        rows.append(ctx.finding('LOGS_FIRST_JSON_SOURCE', source_path, verdict,
            'the initial parseJSON must parse @message; the documented default is @message'))
    return rows
