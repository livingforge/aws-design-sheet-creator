"""Recorded re-reviews that let a later schema, or another region, keep a reviewed ledger state.

A record binds one resource type to the exact schema fingerprint it was reviewed
against. A later change of that fingerprint, a record for another region or a
record for another baseline leaves the original question open. Records never add
rules or change a ledger state; they only stop one specific question from being
re-raised for a schema that a named reviewer has already looked at.
"""
from __future__ import annotations

from datetime import date
import inspect
import json
from pathlib import Path
import re
from urllib.parse import urlparse

FILE = 'schema-reviews.json'
KINDS = ('REGIONAL_APPLICABILITY', 'SCHEMA_CHANGE')
TYPE = re.compile(r'[A-Za-z0-9]+::[A-Za-z0-9]+::[A-Za-z0-9]+')
SHA = re.compile(r'[0-9a-f]{64}')
REGION = re.compile(r'[a-z]{2}(?:-gov)?-[a-z]+-\d+')
REVIEW_ID = re.compile(r'[a-z0-9][a-z0-9.-]{0,127}')
# Wording consumed by the ledger; kept byte-identical to earlier releases.
REGIONAL_QUESTION = 'Regional applicability in {region} has not been reviewed; baseline was {baseline}.'
SCHEMA_QUESTION = ('Pinned schema changed on {date}; re-review registered rules, open questions '
                   'and references against the new schema')
# Any match sends a type to a person; false positives only cost review time.
REGIONAL_TERMS = re.compile(
    r'region|availability[ _-]?zones?|\bAZs?\b|local[ _-]?zones?|wavelength|outposts?|partition|'
    r'\b(?:us|eu|ap|sa|ca|me|af|il|mx|cn)-(?:gov-)?[a-z]+-\d\b|arn:aws-', re.I)
CATEGORIES = ('CARRY_OVER_CANDIDATE', 'REGIONAL_TERMS', 'SCHEMA_CHANGED', 'SCHEMA_CHANGE_CANDIDATE', 'RECORDED')


def empty():
    return {'format_version': 1, 'reviews': []}


def cause(question):
    """Why a type needs review, from the ledger question that raised it."""
    if question.startswith('Regional applicability in '):return 'REGIONAL_APPLICABILITY'
    if question.startswith('Pinned schema changed on '):return 'SCHEMA_CHANGE'
    return 'OPEN_QUESTION'


def _aws_url(url):
    host = urlparse(url).hostname or ''
    return urlparse(url).scheme == 'https' and (host == 'aws.amazon.com' or host.endswith('.aws.amazon.com')
                                                or host.endswith('.amazonaws.com'))


def validate(data):
    """Return the records only if every batch is attributable and every binding is exact."""
    if not isinstance(data, dict) or data.get('format_version') != 1 or not isinstance(data.get('reviews'), list):
        raise ValueError('unsupported schema review records')
    ids, bound = set(), set()
    for review in data['reviews']:
        if not isinstance(review, dict):raise ValueError('invalid schema review record')
        rid = review.get('id')
        if not isinstance(rid, str) or not REVIEW_ID.fullmatch(rid) or rid in ids:
            raise ValueError('schema review IDs must be unique')
        ids.add(rid)
        kind, region = review.get('kind'), review.get('region')
        if kind not in KINDS or not isinstance(region, str) or not REGION.fullmatch(region):
            raise ValueError(f'invalid kind or region: {rid}')
        if kind == 'REGIONAL_APPLICABILITY':
            baseline = review.get('baseline_region')
            if not isinstance(baseline, str) or not REGION.fullmatch(baseline) or baseline == region:
                raise ValueError(f'regional review needs a different baseline region: {rid}')
        try:date.fromisoformat(review.get('reviewed_at'))
        except (TypeError, ValueError):raise ValueError(f'invalid reviewed_at: {rid}') from None
        for key in ('reviewer', 'method', 'rationale'):
            if not isinstance(review.get(key), str) or not review[key].strip():
                raise ValueError(f'schema review needs {key}: {rid}')
        urls = review.get('source_urls')
        if not isinstance(urls, list) or not urls or any(not isinstance(u, str) or not _aws_url(u) for u in urls):
            raise ValueError(f'schema review needs AWS HTTPS sources: {rid}')
        types = review.get('types')
        if not isinstance(types, dict) or not types:raise ValueError(f'schema review needs types: {rid}')
        for name, binding in types.items():
            if not TYPE.fullmatch(name) or not isinstance(binding, dict):raise ValueError(f'invalid type binding: {rid}')
            if not SHA.fullmatch(str(binding.get('type_sha256', ''))):raise ValueError(f'type binding needs a fingerprint: {rid}')
            other = 'baseline_type_sha256' if kind == 'REGIONAL_APPLICABILITY' else 'previous_type_sha256'
            if not SHA.fullmatch(str(binding.get(other, ''))) or set(binding) != {'type_sha256', other}:
                raise ValueError(f'type binding needs {other}: {rid}')
            key = (kind, region, name)
            if key in bound:raise ValueError(f'type reviewed twice for one region: {name}')
            bound.add(key)
    return data


def load(rule_dir):
    path = Path(rule_dir) / FILE
    if not path.exists():return empty()
    return validate(json.loads(path.read_text(encoding='utf-8')))


def accepted(data, kind, region, baseline_region=None):
    """{type: reviewed fingerprint} of records that apply to this region (and baseline)."""
    out = {}
    for review in data['reviews']:
        if review['kind'] != kind or review['region'] != region:continue
        if kind == 'REGIONAL_APPLICABILITY' and review['baseline_region'] != baseline_region:continue
        out.update({t: b['type_sha256'] for t, b in review['types'].items()})
    return out


def _texts(value):
    if isinstance(value, dict):
        for k, v in value.items():
            if k not in ('url', 'source_urls'):yield str(k);yield from _texts(v)
    elif isinstance(value, list):
        for v in value:yield from _texts(v)
    elif value is not None:yield str(value)


def _check_sources():
    from .checks import registry
    registry.check_modules()
    out = {}
    for exact, prefixes, typed, _, fn, _ in registry._CHECKS:
        if not typed:continue
        try:source = inspect.getsource(fn)
        except (OSError, TypeError):source = fn.__name__
        out[(exact, prefixes)] = out.get((exact, prefixes), []) + [(f'{fn.__module__}.{fn.__name__}', source)]
    return out


def regional_terms(kind, entry, rules, references, checks):
    """Where a type's reviewed material mentions regions, zones, partitions or region codes."""
    hits = []
    for question in entry.get('open_questions', []):
        if cause(question) == 'OPEN_QUESTION' and REGIONAL_TERMS.search(question):hits.append('open_question')
    for rule in rules.get(kind, []):
        if any(REGIONAL_TERMS.search(t) for t in _texts({k: v for k, v in rule.items() if k != 'source_urls'})):
            hits.append('rule:' + rule['id'])
    for item in references.get(kind, []):
        if any(REGIONAL_TERMS.search(t) for t in _texts(item)):hits.append('reference:' + item['path'])
    for (exact, prefixes), functions in checks.items():
        if kind in exact or kind.startswith(prefixes):
            hits.extend('check:' + name for name, source in functions if REGIONAL_TERMS.search(source))
    return sorted(set(hits))


def property_diff(old, new):
    """Top-level properties and schema keywords that differ; a reading aid, not a verdict."""
    if old is None:return None
    oldp, newp = old.get('properties', {}), new.get('properties', {})
    return {'added_properties': sorted(set(newp) - set(oldp)), 'removed_properties': sorted(set(oldp) - set(newp)),
            'changed_properties': sorted(k for k in set(oldp) & set(newp) if oldp[k] != newp[k]),
            'changed_definitions': sorted(k for k in set(old.get('definitions', {})) | set(new.get('definitions', {}))
                                          if old.get('definitions', {}).get(k) != new.get('definitions', {}).get(k)),
            'changed_keywords': sorted(k for k in set(old) | set(new)
                                       if k not in ('properties', 'definitions', 'description', 'sourceUrl')
                                       and old.get(k) != new.get(k))}


def queue(ledger, ruleset, references, records, *, region, baseline_region, previous, schemas, old_schemas=None):
    """Classify every reviewed type that this region or schema would re-open.

    previous: {type: fingerprint} the ledger was reviewed against. schemas: the
    candidate archive's {type: schema}. old_schemas: the reviewed archive, when the
    maintainer has it, for property-level differences.
    """
    from .schema_diff import _digest
    rules, refs = {}, {}
    for rule in ruleset.get('rules', []):rules.setdefault(rule['source_type'], []).append(rule)
    for item in references.get('references', []):refs.setdefault(item['source_type'], []).append(item)
    checks = _check_sources()
    regional = baseline_region is not None and baseline_region != region
    carried = accepted(records, 'REGIONAL_APPLICABILITY', region, baseline_region) if regional else {}
    changed_ok = accepted(records, 'SCHEMA_CHANGE', region)
    rows = []
    for kind, entry in sorted(ledger['types'].items()):
        if entry['state'] == 'UNRESEARCHED' or kind not in schemas:continue
        current = _digest(schemas[kind])
        identical = previous.get(kind) == current
        hits = regional_terms(kind, entry, rules, refs, checks)
        row = {'type': kind, 'ledger_state': entry['state'], 'type_sha256': current,
               'previous_type_sha256': previous.get(kind), 'schema_identical': identical, 'regional_terms': hits}
        if not identical:
            row['schema_review'] = 'RECORDED' if changed_ok.get(kind) == current else 'SCHEMA_CHANGED'
            row['property_diff'] = property_diff((old_schemas or {}).get(kind), schemas[kind]) if old_schemas else None
        if regional:
            row['regional_review'] = ('RECORDED' if carried.get(kind) == current else
                                      'CARRY_OVER_CANDIDATE' if identical and not hits else
                                      'REGIONAL_TERMS' if hits else 'SCHEMA_CHANGED')
        if row.get('regional_review', 'RECORDED') == 'RECORDED' and row.get('schema_review', 'RECORDED') == 'RECORDED':
            continue
        rows.append(row)
    counts = {}
    for row in rows:
        for key in ('regional_review', 'schema_review'):
            if key in row:counts.setdefault(key, {}).setdefault(row[key], 0);counts[key][row[key]] += 1
    return {'queue_version': 1, 'region': region, 'baseline_region': baseline_region,
            'counts': {k: dict(sorted(v.items())) for k, v in sorted(counts.items())}, 'types': rows,
            'notes': ['CARRY_OVER_CANDIDATE は機械的な候補です。記録するまで台帳の質問は残ります。',
                      '地域語の検出は保守的です。検出された型は人が確認します。']}


def record(records, queue_data, *, kind, select, review_id, reviewer, method, rationale, source_urls, reviewed_at, types=None):
    """Append one attributable batch built from queue rows; validated before it is returned."""
    if kind == 'REGIONAL_APPLICABILITY':
        rows = [r for r in queue_data['types'] if r.get('regional_review') == select]
        binding = lambda r: {'type_sha256': r['type_sha256'], 'baseline_type_sha256': r['previous_type_sha256']}
    else:
        rows = [r for r in queue_data['types'] if r.get('schema_review') == select]
        binding = lambda r: {'type_sha256': r['type_sha256'], 'previous_type_sha256': r['previous_type_sha256']}
    if types is not None:
        missing = set(types) - {r['type'] for r in rows}
        if missing:raise ValueError('types not in the selected queue category: ' + ', '.join(sorted(missing)))
        rows = [r for r in rows if r['type'] in set(types)]
    if not rows:raise ValueError('no queue rows selected')
    if any(r['previous_type_sha256'] is None for r in rows):raise ValueError('selected types lack a reviewed fingerprint')
    batch = {'id': review_id, 'kind': kind, 'region': queue_data['region'],
             **({'baseline_region': queue_data['baseline_region']} if kind == 'REGIONAL_APPLICABILITY' else {}),
             'reviewed_at': reviewed_at, 'reviewer': reviewer, 'method': method, 'rationale': rationale,
             'source_urls': list(source_urls), 'types': {r['type']: binding(r) for r in rows}}
    return validate({**records, 'reviews': [*records['reviews'], batch]})
