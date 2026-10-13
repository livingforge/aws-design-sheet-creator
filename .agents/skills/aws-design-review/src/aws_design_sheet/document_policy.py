"""Evaluate human-declared project constraints against effective design values."""
from collections import Counter
from dataclasses import dataclass
import hashlib
import json

from .document_policy_model import PolicyEvaluation, path_parts

LIMITATIONS = [
    '案件方針の宣言範囲だけを検査する。AWS仕様全体の禁止事項や設計全体の合格ではない。',
    'CFNの比較値、外部値、参照先の実値、既定値、秘密を取り込まない。',
    '原文の意味・業務フロー・実AWS権限・性能・疎通・変更影響は評価しない。',
    '要件にルールが関連付いていても、その要件全体を網羅したとは扱わない。',
    '配列の*は全要素が対象。空配列・未解決・欠落は要確認。並べ替えで添字の追跡位置は変わる。',
    '明示的な例外はEXEMPTEDとして残し、PASSや要件全体の承認とは扱わない。',
]
MAX_SELECTIONS = 10000


@dataclass
class Node:
    value: object
    state: str
    input_pointer: str
    sources: list
    pointer_role: str = 'VALUE'


def token(value): return str(value).replace('~', '~0').replace('/', '~1')


def decision(setting, pointer, inherited=()):
    sources = list(dict.fromkeys([*inherited, *setting.sources]))
    states = {'DEFAULT': 'DEFAULT_UNRESOLVED', 'OMITTED': 'OMITTED', 'RESOURCE_REF': 'INTERNAL_REFERENCE',
              'EXTERNAL_REF': 'EXTERNAL_REFERENCE', 'SECRET_REF': 'SECRET_REFERENCE', 'EXPRESSION': 'EXPRESSION_UNRESOLVED'}
    if setting.status != 'DECIDED' or setting.mode in states:
        return Node(None, setting.status if setting.status != 'DECIDED' else states[setting.mode], pointer, sources, 'DECLARATION')
    def walk(value, location):
        if setting.mode == 'COMPOSITE' and isinstance(value, dict) and set(value) == {'$design'}:
            from .document_v11 import SchemaSetting
            return decision(SchemaSetting.model_validate(value['$design']), location + '/$design', sources)
        if isinstance(value, dict): value = {k: walk(v, location + '/' + token(k)) for k, v in value.items()}
        elif isinstance(value, list): value = [walk(v, location + '/' + str(i)) for i, v in enumerate(value)]
        return Node(value, 'VALUE', location, sources)
    return walk(setting.value, pointer + '/value')


def effective_nodes(document, resource_id):
    values = {}
    for item in document.items:
        if item.resource_id == resource_id and item.origin != 'cfn_only':
            values[item.name] = decision(item.expected, item.input_pointer)
    index = next(i for i, r in enumerate(document.design.resources) if r.id == resource_id)
    return Node(values, 'VALUE', f'/resources/{index}/settings', [], 'CONTAINER')


def select(root, selector):
    frontier = [('/properties', root)]
    for part in path_parts(selector):
        following = []
        for path, node in frontier:
            target = path + '/' + token(part)
            if node.state != 'VALUE':
                following.append((target, Node(None, node.state, node.input_pointer, node.sources, 'PARENT_DECLARATION')))
            elif part == '*':
                if isinstance(node.value, list) and node.value:
                    following.extend((path + '/' + str(i), child) for i, child in enumerate(node.value))
                else:
                    state = 'EMPTY_SELECTION' if node.value == [] else 'SELECTOR_NOT_ARRAY'
                    following.append((target, Node(None, state, node.input_pointer, node.sources, 'CONTAINER')))
            elif isinstance(node.value, dict) and part in node.value:
                following.append((target, node.value[part]))
            elif isinstance(node.value, list) and part.isdigit() and int(part) < len(node.value):
                following.append((target, node.value[int(part)]))
            else:
                following.append((target, Node(None, 'MISSING', node.input_pointer, node.sources, 'NEAREST_PARENT')))
            if len(following) > MAX_SELECTIONS: raise ValueError('policy selection limit')
        frontier = following
    return frontier


def compare(node, predicate):
    if node.state != 'VALUE': return None
    if isinstance(node.value, (dict, list)): return None  # only scalar assertions in this version
    return any(type(node.value) is type(wanted) and node.value == wanted for wanted in predicate.values)


def evidence_trace(path, node, resource_id, environment):
    top = path_parts(path)[0]
    return {'resource_id': resource_id, 'item_id': resource_id + '.' + top,
            'row_id': environment + '/' + resource_id + '.' + top, 'path': path,
            'input_pointer': node.input_pointer, 'pointer_role': node.pointer_role,
            'input_state': node.state, 'source_ids': node.sources,
            'actual': node.value if node.state == 'VALUE' and not isinstance(node.value, (dict, list)) else None,
            'actual_available': node.state == 'VALUE' and not isinstance(node.value, (dict, list))}


def evaluate(document):
    spec, environment = document.design, document.environment_id
    evaluation = PolicyEvaluation(limitations=list(LIMITATIONS), provenance={
        'input_sha256': document.input_sha256, 'environment_id': environment,
        'value_source': 'EFFECTIVE_DESIGN_INPUT_ONLY', 'comparison_cfn_used': False,
        'declaration_method': 'EXPLICIT_HUMAN_MAPPING', 'all_requirements_evaluated': False})
    registered = {r.requirement_id for r in spec.project_policies}
    evaluation.requirement_coverage = [{'requirement_id': r.id,
        'policy_ids': [p.id for p in spec.project_policies if p.requirement_id == r.id],
        'state': 'DECLARED_RULES_ONLY' if r.id in registered else 'UNREGISTERED',
        'semantic_coverage': 'NOT_ASSESSED'} for r in spec.requirements]
    if not spec.project_policies: return evaluation
    sources = {s.id: s.model_dump(mode='json') for s in spec.sources}
    row_count = 0
    try:
        for rule_index, rule in enumerate(spec.project_policies):
            root = effective_nodes(document, rule.resource_id)
            condition_details = []
            conditions = []
            for index, condition in enumerate(rule.when):
                results = []
                for path, node in select(root, condition.path):
                    verdict = compare(node, condition); results.append(verdict)
                    condition_details.append({'predicate_index': index, 'selector': condition.path,
                        'operator': condition.operator, 'expected': condition.values, 'matched': verdict,
                        'trace': evidence_trace(path, node, rule.resource_id, environment)})
                conditions.append(False if False in results else None if None in results else True)
            active = False if False in conditions else None if None in conditions else True
            for path, node in select(root, rule.path):
                row_count += 1
                if row_count > MAX_SELECTIONS: raise ValueError('policy result limit')
                matched = compare(node, rule)
                exception = next((x for x in spec.policy_exceptions if x.policy_id == rule.id and path in x.paths and environment in x.environments), None)
                if environment not in rule.environments:
                    verdict, reason = 'NOT_APPLICABLE', 'ENVIRONMENT_OUTSIDE_DECLARED_SCOPE'
                elif rule.confirmation != 'CONFIRMED':
                    verdict, reason = 'NEEDS_REVIEW', 'POLICY_DECLARATION_UNCONFIRMED'
                elif active is False:
                    verdict, reason = 'NOT_APPLICABLE', 'DECLARED_CONDITION_FALSE'
                elif active is None:
                    verdict, reason = 'NEEDS_REVIEW', 'DECLARED_CONDITION_UNKNOWN'
                elif matched is None:
                    verdict, reason = 'NEEDS_REVIEW', 'VALUE_MISSING_UNRESOLVED_OR_NOT_SCALAR'
                elif matched:
                    verdict, reason = 'PASS', 'MATCHES_EXPLICIT_PROJECT_POLICY'
                elif exception and exception.confirmation == 'CONFIRMED':
                    verdict, reason = 'EXEMPTED', 'EXPLICIT_SCOPED_EXCEPTION'
                else:
                    verdict, reason = 'FAIL', 'PROJECT_POLICY_MISMATCH'
                    if exception: reason += '_EXCEPTION_UNCONFIRMED'
                identifier = hashlib.sha256(json.dumps([environment, rule.id, path], ensure_ascii=False).encode()).hexdigest()[:20]
                evaluation.rows.append({'policy_check_id': 'policy-' + identifier, 'policy_id': rule.id,
                    'requirement_id': rule.requirement_id, 'resource_id': rule.resource_id, 'environment_id': environment,
                    'selector': rule.path, 'path': path, 'operator': rule.operator, 'expected': rule.values,
                    'result': verdict, 'reason': reason, 'condition_result': 'TRUE' if active is True else 'FALSE' if active is False else 'UNKNOWN',
                    'conditions': condition_details, 'confirmation': rule.confirmation, 'rationale': rule.rationale,
                    'trace': evidence_trace(path, node, rule.resource_id, environment),
                    'policy_sources': [sources[s] for s in rule.sources],
                    'policy_input_pointer': f'/project_policies/{rule_index}',
                    'requirement_input_pointer': f'/requirements/{next(i for i, r in enumerate(spec.requirements) if r.id == rule.requirement_id)}',
                    'input_sources': [sources[s] for s in node.sources],
                    'exception': exception.model_dump(mode='json') if exception else None,
                    'exception_sources': [sources[s] for s in exception.sources] if exception else [],
                    'authority': 'PROJECT_POLICY', 'meaning': 'declared project condition only; not AWS-wide prohibition or real approval'})
        counts = Counter(r['result'] for r in evaluation.rows)
        unregistered = [r['requirement_id'] for r in evaluation.requirement_coverage if r['state'] == 'UNREGISTERED']
        evaluation.status = 'COMPLETE'
        evaluation.summary = {'registered_policies': len(spec.project_policies), 'result_rows': len(evaluation.rows),
            'results': dict(counts), 'declared_requirements': len(spec.requirements),
            'requirements_with_rules': len(registered), 'unregistered_requirements': unregistered,
            'all_requirements_evaluated': False}
        evaluation.assessment = ('NONCOMPLIANT' if counts['FAIL'] else 'REVIEW' if counts['NEEDS_REVIEW'] or counts['EXEMPTED']
            or unregistered else 'NO_APPLICABLE_RULES' if counts['NOT_APPLICABLE'] == len(evaluation.rows) else 'COMPLIANT_WITHIN_DECLARED_SCOPE')
    except Exception:
        # Partial results are retained as evidence, but a failed evaluator cannot pass.
        evaluation.status = 'FAILED'; evaluation.assessment = 'ERROR'
        evaluation.summary = {'error_code': 'POLICY_EVALUATION_FAILED', 'all_requirements_evaluated': False}
    return evaluation
