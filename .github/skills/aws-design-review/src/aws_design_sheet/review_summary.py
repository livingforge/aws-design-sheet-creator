"""Lossless presentation of review findings. This module never changes verdicts.

Only generic schema uncertainty from one explicitly traced, non-secret String
input can be combined. Reference resolution, semantic rules, unknown causes,
mixed severities and different template/scope contexts remain separate.
"""
from __future__ import annotations

from .models import Design, ValueState


def _unknown_paths(value, path):
    if isinstance(value, dict):
        if value == {'$state': 'UNRESOLVED'}:
            return {path}
        return set().union(*(_unknown_paths(v, path + '/' + str(k).replace('~', '~0').replace('/', '~1'))
                             for k, v in value.items()))
    if isinstance(value, list):
        return set().union(*(_unknown_paths(v, f'{path}/{i}') for i, v in enumerate(value)))
    return set()


def _input_hints(resource, finding):
    if resource is None:
        return None
    context = resource.template
    path = finding.get('path')
    field = resource.field(path) if path else None
    if not context or context.state != ValueState.KNOWN or not field:
        return None
    selected = field.selected()
    paths = {path} if field.state == ValueState.UNRESOLVED else (
        _unknown_paths(selected.value, path) if field.state == ValueState.KNOWN and selected else set())
    if not paths or any(p not in context.parameter_hints for p in paths):
        return None
    hints = [context.parameter_hints[p] for p in paths]
    return hints


def _cause(resource, finding):
    hints = _input_hints(resource, finding)
    if finding.get('rule_id') != 'SCHEMA_UNCERTAIN' or not hints or any(
            h.type != 'String' or h.no_echo is True or len(h.inputs) != 1 for h in hints):
        return None
    inputs = {h.inputs[0] for h in hints}
    if len(inputs) != 1:
        return None
    source = next(iter(inputs))
    if not source.startswith('parameter:') and source != 'pseudo:AWS::StackName':
        return None
    return (resource.template.id, resource.scope.environment, resource.scope.account, resource.scope.region,
            source, finding.get('severity'))


def build_review_summary(design: Design, results: list[dict], coverage: list[dict]) -> dict:
    resources = {r.id: r for r in design.resources}
    groups = {}
    items = []
    for index, finding in enumerate(results):
        if finding.get('verdict') != 'NEEDS_REVIEW':
            continue
        resource = resources.get(finding.get('resource_id'))
        cause = _cause(resource, finding)
        key = ('input', *cause) if cause else ('finding', index)
        if key not in groups:
            source = cause[4] if cause else None
            if source:
                name = source.split(':', 1)[1]
                unknown = f"{name} の文字列値が未確定"
                action = (f"対象テンプレートの実行時スタック名 {name} を確認する。" if source.startswith('pseudo:') else
                          f"対象テンプレートのパラメーター {name} に渡す文字列を確認する。")
                action += "値を反映して再検査し、各明細の制約を確認する。"
                why = "同じ文字列入力が未確定のため、各プロパティの検査が完了していない。"
            else:
                unknown = f"{resource.name if resource else finding.get('resource_id') or '対象未指定'} {finding.get('path') or ''}"
                why = finding.get('reason', '')
                action = "元の理由・依存項目・根拠を確認する。入力元や確認行為が同一と断定できないため、独立した確認として残す。"
                hints = _input_hints(resource, finding) or []
                explicit = sorted({p for h in hints for p in h.inputs})
                if explicit:
                    names = '、'.join(p.split(':', 1)[1] for p in explicit)
                    unknown += f"（未確定入力: {names}）"
                    if any(h.no_echo is True for h in hints):
                        action = f"{names} の供給元と、安全に制約を検証する方法を確認する。秘密値を報告書へ記載しない。"
                    elif any(h.type and (h.type.startswith(('AWS::', 'List<')) or h.type == 'CommaDelimitedList') for h in hints):
                        action = f"{names} に渡す一覧/IDと参照先の構成情報を確認する。AZ・VPC・経路等の確認は元の各指摘に従って個別に行う。"
                    else:
                        action = f"{names} の入力または実行コンテキストを確認する。複数の原因・条件があり得るため、元の指摘ごとに再確認する。"
            item = {'id': f'review-{len(items) + 1:03}', 'verdict': 'NEEDS_REVIEW',
                    'severity': finding.get('severity'), 'input': source,
                    'context': {'template': cause[0], 'environment': cause[1], 'account': cause[2], 'region': cause[3]} if cause else None,
                    'unknown': unknown, 'why': why, 'action': action, 'result_indexes': [],
                    'result_refs': [], 'rule_ids': [], 'resource_ids': [], 'evidence_ids': [], 'coverage_indexes': []}
            groups[key] = item
            items.append(item)
        item = groups[key]
        item['result_indexes'].append(index)
        item['result_refs'].append(f'/results/{index}')
        for target, source_key in [('rule_ids', 'rule_id'), ('resource_ids', 'resource_id')]:
            if finding.get(source_key) not in item[target]:
                item[target].append(finding.get(source_key))
        item['evidence_ids'] = sorted(set(item['evidence_ids']) | set(finding.get('evidence_ids', [])))
    for item in items:
        item['grouped'] = len(item['result_indexes']) > 1
        item['coverage_indexes'] = [i for i, row in enumerate(coverage)
                                    if row.get('resource_id') is None or row.get('resource_id') in item['resource_ids']]
    return {'version': '1', 'raw_needs_review_count': sum(len(i['result_indexes']) for i in items),
            'item_count': len(items), 'items': items, 'coverage_ref': '/coverage',
            'note': '確認項目数は表示上の集約数。判定・重大度・未検査範囲は変わらず、人間の実作業数や時間短縮の実測ではない。'}


def validate_review_summary(summary: dict, results: list[dict], coverage: list[dict] | None = None) -> None:
    """Reject stale/partial display data rather than silently omitting findings."""
    expected = [i for i, row in enumerate(results) if row.get('verdict') == 'NEEDS_REVIEW']
    actual = [i for item in summary['items'] for i in item['result_indexes']]
    if sorted(actual) != expected or summary['raw_needs_review_count'] != len(expected) or summary['item_count'] != len(summary['items']):
        raise ValueError('review summary does not cover each NEEDS_REVIEW result exactly once')
    for item in summary['items']:
        if not item['result_indexes'] or item['verdict'] != 'NEEDS_REVIEW' or any(
                results[i].get('severity') != item['severity'] for i in item['result_indexes']):
            raise ValueError('review summary has inconsistent verdict or severity')
        members = [results[i] for i in item['result_indexes']]
        if (item['result_refs'] != [f'/results/{i}' for i in item['result_indexes']]
                or set(item['rule_ids']) != {r['rule_id'] for r in members}
                or set(item['resource_ids']) != {r.get('resource_id') for r in members}
                or set(item['evidence_ids']) != {e for r in members for e in r.get('evidence_ids', [])}):
            raise ValueError('review summary has stale references, rules, targets or evidence')
        if coverage is not None:
            expected_coverage = [i for i, row in enumerate(coverage)
                                 if row.get('resource_id') is None or row.get('resource_id') in item['resource_ids']]
            if item['coverage_indexes'] != expected_coverage:
                raise ValueError('review summary has incomplete coverage references')
