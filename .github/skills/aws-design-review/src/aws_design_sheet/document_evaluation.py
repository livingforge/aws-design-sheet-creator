"""Opt-in, local bridge from effective document settings to the existing checker.

CFN supplied for comparison is deliberately not an input to this adapter. The
synthetic lint templates isolate resources: the document format does not assert
stack membership, account identity, Ref/GetAtt attributes or DependsOn order.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import Field

from .models import StrictModel, Design, ValueState

VERSION = '1.0'
ROOT = Path(__file__).resolve().parents[2]
UNKNOWN = {'$state': 'UNRESOLVED'}
OMIT = object()
LIMITATIONS = [
    '評価対象は選択環境の明示された設計設定。比較用CFNから値・条件・パラメータを補わない。',
    'AWS実環境、性能、権限の実効性、疎通、業務要件・APP・Q01–06の合否は検査しない。',
    'アカウントとスタック所属は未宣言。CFNは資源ごとに分離した検査用合成物で、デプロイ用ではない。',
    '内部参照は宣言先との関係だけを検査。実値・Ref/GetAtt属性・依存順序は補完しない。',
    '式・既定値・外部参照・秘密参照は解決せず、未知値用パラメータにDefaultを設定しない。',
    '既存検査器と固定スキーマの範囲に限定。検出なし・生成成功・比較一致は設計全体の合格を意味しない。',
]


class Evaluation(StrictModel):
    bridge_version: str = VERSION
    status: Literal['NOT_EVALUATED', 'COMPLETE', 'FAILED', 'SKIPPED'] = 'NOT_EVALUATED'
    assessment: Literal['NOT_EVALUATED', 'FAIL', 'REVIEW', 'NO_FINDINGS', 'ERROR'] = 'NOT_EVALUATED'
    stages: dict = Field(default_factory=dict)
    summary: dict = Field(default_factory=dict)
    results: list[dict] = Field(default_factory=list)
    coverage: list[dict] = Field(default_factory=list)
    mappings: list[dict] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=lambda: list(LIMITATIONS))


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def stable(prefix, value):
    return prefix + hashlib.sha256(encoded(value).encode()).hexdigest()[:20]


def token(value):
    return str(value).replace('~', '~0').replace('/', '~1')


def adapt(document):
    """Return a valid legacy Design and explicit pointer/source/unknown mappings."""
    from .document_v11 import SchemaSetting
    env = next(e for e in document.design.environments if e.id == document.environment_id)
    resources = {r.id: r for r in document.design.resources}
    lines, evidence, mappings, relations, coverage = [], [], [], [], []
    fields = {r: [] for r in resources}

    def record(resource_id, path, setting, item, pointer):
        ident = stable('bridge-', [env.id, resource_id, path])
        data = {'environment_id': env.id, 'resource_id': resource_id, 'path': path,
                'item_id': item.item_id, 'row_id': item.row_id, 'input_pointer': pointer,
                'origin': item.origin, 'source_ids': list(setting.sources),
                'status': setting.status, 'mode': setting.mode}
        mappings.append({**data, 'evidence_id': ident})
        line = encoded({**data, 'setting': setting.model_dump(mode='json')})
        lines.append(line)
        evidence.append({'id': ident, 'document_id': 'bridge-effective-settings',
                         'start_line': len(lines), 'end_line': len(lines), 'excerpt': line})
        return ident

    def unknown(resource_id, path, reason, evidence_id):
        coverage.append({'kind': 'BRIDGE_UNKNOWN_VALUE', 'resource_id': resource_id,
                         'path': path, 'reason': reason, 'evidence_ids': [evidence_id]})
        return dict(UNKNOWN)

    def convert(setting, resource_id, path, item, pointer):
        eid = record(resource_id, path, setting, item, pointer)
        if setting.status == 'NOT_APPLICABLE' or setting.mode == 'OMITTED':
            return OMIT, eid
        if setting.status != 'DECIDED' or setting.mode in ('DEFAULT', 'EXTERNAL_REF', 'SECRET_REF', 'EXPRESSION'):
            return unknown(resource_id, path, setting.mode or setting.status, eid), eid
        if setting.mode == 'RESOURCE_REF':
            values = []
            for i, target in enumerate(setting.ref if isinstance(setting.ref, list) else [setting.ref]):
                refpath = path + '/' + str(i) if isinstance(setting.ref, list) else path
                relations.append({'id': stable('relation-', [resource_id, refpath]),
                    'source_resource_id': resource_id, 'source_path': refpath,
                    'target_resource_id': target, 'expected_target_type': resources[target].type,
                    'evidence_ids': [eid]})
                values.append(unknown(resource_id, refpath, 'INTERNAL_REFERENCE_VALUE_UNRESOLVED', eid))
            return (values if isinstance(setting.ref, list) else values[0]), eid

        def walk(value, subpath, input_path):
            if setting.mode == 'COMPOSITE' and isinstance(value, dict) and set(value) == {'$design'}:
                return convert(SchemaSetting.model_validate(value['$design']), resource_id,
                               subpath, item, input_path + '/$design')[0]
            # Literal CFN-shaped maps / legacy markers must not become executable expressions.
            if (isinstance(value, dict) and (value == UNKNOWN or 'Ref' in value or any(k.startswith('Fn::') for k in value))
                    or isinstance(value, str) and value.startswith('@AWS::')):
                return unknown(resource_id, subpath, 'LITERAL_REPRESENTATION_UNSUPPORTED', eid)
            if isinstance(value, dict):
                result = {}
                for key, child in value.items():
                    converted = walk(child, subpath + '/' + token(key), input_path + '/' + token(key))
                    if converted is not OMIT: result[key] = converted
                return result
            if isinstance(value, list):
                result = []
                for i, child in enumerate(value):
                    converted = walk(child, subpath + '/' + str(i), input_path + '/' + str(i))
                    # Removing an array slot changes reference paths; retain its unknown position.
                    if converted is OMIT: converted = unknown(resource_id, subpath + '/' + str(i), 'OMITTED_ARRAY_SLOT', eid)
                    result.append(converted)
                return result
            return value
        return walk(setting.value, path, pointer + '/value'), eid

    for item in document.items:
        if item.origin == 'cfn_only': continue
        path = '/properties/' + token(item.name)
        value, eid = convert(item.expected, item.resource_id, path, item, item.input_pointer)
        if value is OMIT: continue
        unresolved = value == UNKNOWN
        field = {'path': path, 'state': 'UNRESOLVED' if unresolved else 'KNOWN',
                 'candidates': [{'id': eid, 'raw': '[normalized effective design setting]',
                                 'value': value, 'evidence_ids': [eid], 'origin': 'document-bridge'}]}
        if not unresolved: field['selected_candidate_id'] = eid
        fields[item.resource_id].append(field)
    # A resource without settings still has traceable source evidence.
    for index, resource in enumerate(resources.values()):
        line = encoded({'resource_id': resource.id, 'input_pointer': f'/resources/{index}',
                        'source_ids': resource.sources, 'type': resource.type})
        lines.append(line)
        evidence.append({'id': 'resource-' + resource.id, 'document_id': 'bridge-effective-settings',
                         'start_line': len(lines), 'end_line': len(lines), 'excerpt': line})
    source = '\n'.join(lines)
    data = {'project': document.design.system.id, 'environment': env.id, 'account': 'UNDECLARED',
            'region': env.region, 'extractor_version': 'document-bridge-' + VERSION,
            'documents': [{'id': 'bridge-effective-settings', 'name': 'Normalized effective settings (not original source lines)',
                'version': VERSION, 'text': source, 'sha256': hashlib.sha256(source.encode()).hexdigest(),
                'extracted_ranges': [[1, len(lines)]]}], 'evidence': evidence,
            'resources': [{'id': r.id, 'type': r.type, 'name': r.id,
                           'scope': {'environment': env.id, 'account': 'UNDECLARED', 'region': env.region},
                           'fields': fields[r.id]} for r in resources.values()],
            'relations': relations,
            'requirements': [{'id': n.id, 'description': n.text} for n in document.design.requirements]}
    for kind, items in [('CONNECTION', document.design.connections), ('OPERATION', document.design.operations),
                        ('ISSUE', document.design.issues)]:
        for item in items:
            coverage.append({'kind': 'BRIDGE_' + kind, 'resource_id': None, 'path': None,
                             'reason': 'Declaration retained; no semantic/business rule is inferred.', 'declaration_id': item.id})
    coverage.append({'kind': 'BRIDGE_SCOPE', 'resource_id': None, 'path': None,
                     'reason': 'Account, stack membership, live AWS and business intent are not established.'})
    return Design.model_validate(data), mappings, coverage


def run_checker(design):
    from .checker import Checker
    checker = Checker(ROOT / 'schemas', ROOT / 'profiles/document-bridge.json',
                      ROOT / 'rules/ledger.json', ROOT / 'rules/ruleset.json',
                      ROOT / 'rules/references.json', cfn_lint=False)
    try: return checker.check(design)
    finally:
        if checker.archive: checker.archive.close()


def run_linter(design):
    from .cfn_export import export_templates
    from .cfn_lint_check import lint_design, CFN_LINT_VERSION
    from .cfn_compat import VERSION as compat_version
    from .models import TemplateContext
    isolated = design.model_copy(deep=True)
    for resource in isolated.resources:
        resource.template = TemplateContext(id='synthetic-' + resource.id, depends_on=None,
                                            evidence_ids=['resource-' + resource.id])
    exported = export_templates(isolated)
    results, coverage = lint_design(isolated)
    templates = [{'synthetic': True, 'deployable': False, 'resource_ids': e.resource_ids,
                  'placeholders': e.placeholders, 'template': e.template} for e in exported]
    return {'status': 'COMPLETE', 'results': results, 'coverage': coverage,
            'versions': {'cfn_lint': CFN_LINT_VERSION, 'cfn_compat': compat_version}, 'templates': templates}


def evaluate(document):
    evaluation = Evaluation()
    evaluation.provenance = {'input_sha256': document.input_sha256, 'environment_id': document.environment_id,
                             'cfn_used_for_evaluation': False, 'account': 'UNDECLARED',
                             'comparison_cfn_sha256': document.cfn_sha256}
    try:
        design, evaluation.mappings, evaluation.coverage = adapt(document)
    except Exception:
        evaluation.status = 'FAILED'; evaluation.assessment = 'ERROR'
        evaluation.stages['adapter'] = {'status': 'FAILED', 'reason': 'Adapter failed; source values are not logged.'}
        for name in ('checker', 'cfn_lint'):
            evaluation.stages[name] = {'status': 'SKIPPED', 'reason': 'Adapter did not complete'}
        return evaluation
    evaluation.stages['adapter'] = {'status': 'COMPLETE', 'resources': len(design.resources)}
    evaluation.provenance['adapter_input_sha256'] = hashlib.sha256(design.model_dump_json().encode()).hexdigest()
    from .document_catalog import catalog
    if design.region != catalog().manifest['region']:
        evaluation.status = 'SKIPPED'; evaluation.assessment = 'NOT_EVALUATED'
        for name in ('checker', 'cfn_lint'): evaluation.stages[name] = {'status': 'SKIPPED', 'reason': 'Unsupported region'}
        _trace(evaluation, document)
        return evaluation
    unknown_resources = {r['resource_id'] for r in evaluation.coverage if r['kind'] == 'BRIDGE_UNKNOWN_VALUE'}
    for name, runner in [('checker', run_checker), ('cfn_lint', run_linter)]:
        try:
            result = runner(design)
            if result.get('status') != 'COMPLETE': raise ValueError('evaluator did not complete')
            evaluation.stages[name] = {'status': 'COMPLETE', 'versions': result.get('versions', {})}
            if name == 'cfn_lint': evaluation.provenance['synthetic_templates'] = result['templates']
            for row in result['results']:
                row = {**row, 'stage': name}
                # Conditions on opaque values and account/stack-wide conclusions are not proofs.
                independent = {'CFN_LINT.E3030', 'CFN_LINT.E3031', 'CFN_LINT.E3012', 'CFN_LINT.E3033',
                               'CFN_LINT.E3034', 'CFN_LINT.E9001'}
                uncertain = (row.get('resource_id') in unknown_resources and
                             (not row.get('path') or row['path'] == '/properties' or
                              name == 'cfn_lint' and row['rule_id'] not in independent))
                scope_rule = any(word in row['rule_id'] for word in ('TEMPLATE_', 'REGION_UNIQUE', 'UNIQUENESS', 'SCOPE'))
                if row['verdict'] in ('PASS', 'FAIL') and (uncertain or scope_rule):
                    row['evaluator_verdict'] = row['verdict']; row['verdict'] = 'NEEDS_REVIEW'
                    row['bridge_reason'] = 'Unknown condition or undeclared account/stack context; evaluator finding requires review.'
                evaluation.results.append(row)
            evaluation.coverage.extend({**r, 'stage': name} for r in result['coverage'])
        except Exception:
            evaluation.stages[name] = {'status': 'FAILED', 'reason': 'Evaluator failed; source values and exception details are not logged.'}
            evaluation.coverage.append({'kind': 'EVALUATOR_FAILED', 'stage': name, 'resource_id': None,
                                        'path': None, 'reason': 'Evaluator did not complete. No success verdict is inferred.'})
    _trace(evaluation, document)
    evaluation.status = 'FAILED' if any(s['status'] == 'FAILED' for s in evaluation.stages.values()) else 'COMPLETE'
    evaluation.summary = {'verdicts': dict(Counter(r['verdict'] for r in evaluation.results)),
                          'coverage': len(evaluation.coverage), 'mapped_settings': len(evaluation.mappings),
                          'resources': len(design.resources)}
    evaluation.assessment = ('ERROR' if evaluation.status == 'FAILED' else
        'FAIL' if any(r['verdict'] == 'FAIL' for r in evaluation.results) else
        'REVIEW' if evaluation.coverage or any(r['verdict'] == 'NEEDS_REVIEW' for r in evaluation.results) else 'NO_FINDINGS')
    return evaluation


def _trace(evaluation, document):
    for rows, prefix in [(evaluation.results, 'evaluation-'), (evaluation.coverage, 'coverage-')]:
        seen = Counter()
        for row in rows:
            identity = [document.environment_id, row.get('stage', 'adapter'), row.get('rule_id', row.get('kind')),
                        row.get('resource_id'), row.get('path')]
            key = encoded(identity); seen[key] += 1
            row['evaluation_id'] = stable(prefix, [*identity, seen[key]])
            resource_id, path = row.get('resource_id'), row.get('path')
            related = [m for m in evaluation.mappings if m['resource_id'] == resource_id and
                       (not path or path == '/properties' or m['path'] == path or m['path'].startswith(path + '/') or path.startswith(m['path'] + '/'))]
            row['trace'] = related
            if resource_id and not related:
                resource_index = next(i for i, r in enumerate(document.design.resources) if r.id == resource_id)
                resource = document.design.resources[resource_index]
                row['resource_input_pointer'] = f'/resources/{resource_index}'
                row['resource_source_ids'] = resource.sources
                row['missing_setting_not_invented'] = True
            row['environment_id'] = document.environment_id
            row['requirement_ids'] = sorted({n.id for n in document.design.requirements if resource_id in n.resources} |
                {n.requirement_id for n in document.design.required_inputs if n.resource_id == resource_id and
                 (not path or path == '/properties' or n.path == path or path.startswith(n.path + '/'))})
            row['requirement_link_semantics'] = 'resource association only; business requirement was not evaluated'
