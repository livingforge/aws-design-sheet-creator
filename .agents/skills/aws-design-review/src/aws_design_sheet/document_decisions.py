"""Basic-design decisions, their outline and explicit traceability to settings.

Decisions are prose policies. Only declared links (settings' decision_ids and a
decision's policy_ids) are traced; no link, scope or value is inferred from text.
"""
from collections import Counter
from typing import Annotated, Literal

from pydantic import Field, JsonValue, model_validator

from .models import StrictModel

ID = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_-]{0,63}$')]

# Chapters of a typical Japanese SI basic design; projects may declare their own.
STANDARD_OUTLINE = [
    ('overview', 'システム概要'), ('non-functional', '非機能要件'), ('account', 'アカウント・リージョン'),
    ('network', 'ネットワーク'), ('compute', 'コンピュート'), ('data', 'データベース・ストレージ'),
    ('edge', '公開・配信'), ('security', 'セキュリティ・認証'), ('monitoring', '監視・ログ'),
    ('backup-dr', 'バックアップ・DR'), ('operations', '運用'),
]
VALUE_MODES = ('LITERAL', 'COMPOSITE', 'RESOURCE_REF', 'EXTERNAL_REF', 'EXPRESSION', 'SECRET_REF')


class Section(StrictModel):
    id: ID
    title: str = Field(min_length=1)
    # A required section without any decision is reported as SECTION_EMPTY.
    required: bool = True


class DecisionScope(StrictModel):
    resources: list[ID] = Field(default_factory=list)
    types: list[str] = Field(default_factory=list)
    environments: list[ID] = Field(default_factory=list)

    @model_validator(mode='after')
    def target(self):
        if not self.resources and not self.types:
            raise ValueError('decision scope requires resources or types')
        return self


class Expansion(StrictModel):
    """An explicitly declared value a DECIDED decision supplies to absent top-level settings."""
    property: str = Field(min_length=1)
    mode: Literal['LITERAL', 'RESOURCE_REF', 'EXTERNAL_REF']
    value: JsonValue = None
    ref: str | list[str] | None = None
    # Secret values are never distributed by a decision.
    classification: Literal['PUBLIC', 'INTERNAL', 'CONFIDENTIAL'] = 'INTERNAL'
    environments: list[ID] = Field(default_factory=list)
    # Optional narrowing of the decision scope, for type-specific property names.
    types: list[str] = Field(default_factory=list)
    rationale: str = ''


class Decision(StrictModel):
    id: ID
    section: ID
    title: str = Field(min_length=1)
    statement: str = Field(min_length=1)
    status: Literal['DECIDED', 'UNDECIDED', 'NOT_APPLICABLE'] = 'DECIDED'
    rationale: str = ''
    alternatives: list[str] = Field(default_factory=list)
    requirement_ids: list[ID] = Field(default_factory=list)
    policy_ids: list[ID] = Field(default_factory=list)
    # Declares where settings are expected to realize the decision. Without it
    # the decision stays prose and no realization gap is asserted.
    applies_to: DecisionScope | None = None
    expansions: list[Expansion] = Field(default_factory=list, max_length=64)
    sources: list[ID] = Field(default_factory=list)

    @model_validator(mode='after')
    def expandable(self):
        if self.expansions and self.applies_to is None:raise ValueError('decision expansions require applies_to')
        for e in self.expansions:expanded_setting(self, e)
        return self


def expanded_setting(decision, expansion):
    from .document_v11 import SchemaSetting
    payload = {'value': expansion.value} if expansion.mode == 'LITERAL' else {'ref': expansion.ref}
    note = f'方針 {decision.id} から展開' + ('：' + expansion.rationale if expansion.rationale else '')
    return SchemaSetting(status='DECIDED', mode=expansion.mode, classification=expansion.classification, **payload,
                         rationale=note, sources=decision.sources, decision_ids=[decision.id])


def scope_targets(spec, decision, environment):
    scope = decision.applies_to
    if scope is None or scope.environments and environment not in scope.environments:return []
    return sorted({*scope.resources, *[r.id for r in spec.resources if r.type in scope.types]})


def expansion_targets(spec, decision, expansion, environment):
    if expansion.environments and environment not in expansion.environments:return []
    kinds = {r.id: r.type for r in spec.resources}
    return [r for r in scope_targets(spec, decision, environment) if not expansion.types or kinds[r] in expansion.types]


def expansions(spec, environment):
    """Expansion candidates for one environment. Explicit settings always take precedence."""
    env = next(e for e in spec.environments if e.id == environment)
    overrides = {o.resource_id: o.settings for o in env.overrides}
    resources = {r.id: r for r in spec.resources}
    applied, records = {}, []
    for di, d in enumerate(spec.decisions):
        if d.status != 'DECIDED':continue
        for ei, e in enumerate(d.expansions):
            for rid in expansion_targets(spec, d, e, environment):
                setting = expanded_setting(d, e); pointer = f'/decisions/{di}/expansions/{ei}'
                explicit = overrides.get(rid, {}).get(e.property) or resources[rid].settings.get(e.property)
                if explicit is None:
                    result = 'APPLIED';applied.setdefault(rid, {})[e.property] = (setting, pointer)
                else:
                    same = [explicit.status, explicit.mode, explicit.value, explicit.ref] == [setting.status, setting.mode, setting.value, setting.ref]
                    result = 'MATCHED_EXPLICIT' if same else 'OVERRIDDEN'
                records.append({'expansion_id': f'{d.id}/{ei}', 'decision_id': d.id, 'resource_id': rid, 'property': e.property,
                                'environment_id': environment, 'item_id': rid + '.' + e.property, 'input_pointer': pointer,
                                'result': result, 'setting': setting.model_dump(mode='json', exclude_defaults=True)})
    return applied, records


def outline(spec):
    if spec.design_outline is not None:return spec.design_outline
    return [Section(id=i, title=t) for i, t in STANDARD_OUTLINE]


def validate_decisions(spec):
    from .document_catalog import input_type_inventory
    sections = [s.id for s in outline(spec)]
    if len(sections) != len(set(sections)):raise ValueError('duplicate outline section')
    resources = {r.id for r in spec.resources}; sources = {s.id for s in spec.sources}
    requirements = {r.id for r in spec.requirements}; policies = {p.id for p in spec.project_policies}
    environments = {e.id for e in spec.environments}; kinds = set(input_type_inventory())
    for d in spec.decisions:
        if d.section not in sections:raise ValueError('decision section is not in the outline')
        if set(d.requirement_ids) - requirements:raise ValueError('decision requirement is not declared')
        if set(d.policy_ids) - policies:raise ValueError('decision policy is not declared')
        if set(d.sources) - sources:raise ValueError('invalid source reference')
        for key in ('requirement_ids', 'policy_ids', 'sources', 'alternatives'):
            if len(getattr(d, key)) != len(set(getattr(d, key))):raise ValueError('duplicate decision reference')
        scope = d.applies_to
        if scope:
            if set(scope.resources) - resources:raise ValueError('decision scope resource is not declared')
            if set(scope.types) - kinds:raise ValueError('decision scope type is outside the catalog')
            if set(scope.environments) - environments:raise ValueError('decision scope environment is not declared')
        for e in d.expansions:
            if set(e.environments) - environments or len(e.environments) != len(set(e.environments)):
                raise ValueError('expansion environment is not declared')
            if set(e.types) - kinds:raise ValueError('expansion type is outside the catalog')
    for env in spec.environments:
        # Two expansions for one setting would make precedence implicit.
        seen = set()
        for d in spec.decisions:
            for e in d.expansions:
                for rid in expansion_targets(spec, d, e, env.id):
                    if (rid, e.property) in seen:raise ValueError('ambiguous decision expansion')
                    seen.add((rid, e.property))


def setting_links(item):
    """Declared decision links of an item's expected setting, including composite leaves."""
    from .document_v11 import SchemaSetting, value_resolution
    links = []
    def visit(setting, path, input_pointer):
        for decision_id in setting.decision_ids:
            links.append({'decision_id': decision_id, 'item_id': item.item_id, 'resource_id': item.resource_id,
                          'path': path, 'input_pointer': input_pointer, 'status': setting.status,
                          'mode': setting.mode, 'value_resolution': value_resolution(setting), 'rationale': setting.rationale})
        if setting.mode != 'COMPOSITE':return
        def walk(value, parts, pointer):
            if isinstance(value, dict):
                if set(value) == {'$design'}:
                    visit(SchemaSetting.model_validate(value['$design']), parts, pointer + '/$design');return
                for k, v in value.items():
                    key = str(k).replace('~', '~0').replace('/', '~1');walk(v, parts + '/' + key, pointer + '/' + key)
            elif isinstance(value, list):
                for i, v in enumerate(value):walk(v, parts + '/' + str(i), pointer + '/' + str(i))
        walk(setting.value, path, input_pointer + '/value')
    if item.origin != 'cfn_only':visit(item.expected, '/properties/' + item.name, item.input_pointer)
    return links


def trace(document):
    spec = document.design; env = document.environment_id
    if not spec.decisions and spec.design_outline is None:
        return {'version': '1.0', 'status': 'NOT_CHECKED', 'assessment': 'NOT_CHECKED', 'environment_id': env,
                'summary': {}, 'limitations': ['decisions/design_outline が未宣言のため方針トレースは未実施です。']}
    findings = []
    def finding(kind, code, message, **ids):
        findings.append({'finding_id': ':'.join([code, *(v for v in ids.values() if v)]), 'kind': kind, 'code': code, **ids, 'message': message})
    links = [link for item in document.items for link in setting_links(item)]
    by_decision = {d.id: [l for l in links if l['decision_id'] == d.id] for d in spec.decisions}
    policy_rows = getattr(document.project_policy, 'rows', [])
    expansion_records = getattr(document, 'decision_expansions', [])
    for record in expansion_records:
        if record['result'] == 'OVERRIDDEN':
            finding('CONFLICT', 'EXPANSION_OVERRIDDEN', '方針の展開値と異なる設定が個別に指定されています。例外であれば理由を記載してください。',
                    decision_id=record['decision_id'], item_id=record['item_id'])
    decisions = []
    for d in spec.decisions:
        own = by_decision[d.id]; scope = d.applies_to
        in_env = scope is None or not scope.environments or env in scope.environments
        targets = sorted({*scope.resources, *[r.id for r in spec.resources if r.type in scope.types]}) if scope and in_env else []
        covered = sorted({l['resource_id'] for l in own if l['status'] == 'DECIDED' and l['resource_id'] in targets})
        pending = sorted({l['resource_id'] for l in own if l['status'] == 'UNDECIDED'} & set(targets) - set(covered))
        if d.status == 'NOT_APPLICABLE':state = 'NOT_APPLICABLE'
        elif d.status == 'UNDECIDED':state = 'UNDECIDED'
        elif scope is None:state = 'LINKED' if own else 'DOCUMENT_ONLY'
        elif not in_env:state = 'NOT_IN_ENVIRONMENT'
        elif not targets:state = 'NO_TARGET_IN_SCOPE'
        else:state = 'REALIZED' if len(covered) == len(targets) else 'PARTIAL' if covered else 'NOT_REALIZED'
        decided = [l for l in own if l['status'] == 'DECIDED']
        if d.status == 'UNDECIDED':
            finding('OPEN', 'DECISION_UNDECIDED', '方針が未決定です。', decision_id=d.id)
            for l in decided:finding('CONFLICT', 'DECISION_UNDECIDED_BUT_SETTING_DECIDED',
                                     '未決定の方針を根拠に、設定が決定済みになっています。', decision_id=d.id, item_id=l['item_id'], path=l['path'])
        if d.status == 'NOT_APPLICABLE':
            for l in decided:finding('CONFLICT', 'DECISION_NOT_APPLICABLE_BUT_LINKED',
                                     '適用外の方針を根拠にした決定済みの設定があります。', decision_id=d.id, item_id=l['item_id'], path=l['path'])
        if d.status == 'DECIDED' and scope and in_env:
            if not targets:finding('GAP', 'NO_TARGET_IN_SCOPE', '適用範囲に該当するリソースが入力にありません。', decision_id=d.id)
            for r in targets:
                if r in covered:continue
                if r in pending:finding('OPEN', 'REALIZING_SETTING_UNDECIDED', '方針を具体化する設定が未決定です。', decision_id=d.id, resource_id=r)
                else:finding('GAP', 'DECISION_NOT_REALIZED', '適用範囲のリソースに、この方針を参照する設定がありません。', decision_id=d.id, resource_id=r)
            for l in own:
                if l['resource_id'] not in targets:finding('CONFLICT', 'LINK_OUTSIDE_DECISION_SCOPE',
                    '方針の適用範囲外のリソースが、この方針を参照しています。', decision_id=d.id, item_id=l['item_id'], path=l['path'])
        rows = [r for r in policy_rows if r.get('policy_id') in d.policy_ids]
        decisions.append({'decision_id': d.id, 'section': d.section, 'title': d.title, 'status': d.status,
            'requirement_ids': d.requirement_ids, 'policy_ids': d.policy_ids, 'realization': state,
            'mechanization': 'CHECKED' if d.policy_ids else 'TRACED' if own else 'DESCRIBED',
            'scope_resources': targets, 'covered_resources': covered, 'pending_resources': pending,
            'linked_item_ids': sorted({l['item_id'] for l in own}),
            'policy_results': dict(sorted(Counter(r['result'] for r in rows).items())),
            'expansions_declared': len(d.expansions),
            'expansion_results': dict(sorted(Counter(r['result'] for r in expansion_records if r['decision_id'] == d.id).items()))})
    sections = []
    for s in outline(spec):
        ids = [d.id for d in spec.decisions if d.section == s.id]
        sections.append({'section_id': s.id, 'title': s.title, 'required': s.required, 'decision_ids': ids})
        if s.required and not ids:finding('GAP', 'SECTION_EMPTY', '必須の章に方針が記載されていません。', section_id=s.id)
    cited = {r for d in spec.decisions for r in d.requirement_ids}
    for r in spec.requirements:
        if r.status == 'DECIDED' and r.id not in cited:
            finding('GAP', 'REQUIREMENT_WITHOUT_DECISION', '要件を根拠にした方針がありません。', requirement_id=r.id)
    # A declared REFERENCE connection already documents why a reference exists.
    connected = {(c.source, c.property) for c in spec.connections if c.kind == 'REFERENCE'}
    for item in document.items:
        e = item.expected
        if e.mode == 'RESOURCE_REF' and (item.resource_id, item.name) in connected:continue
        if (item.origin != 'cfn_only' and e.status == 'DECIDED' and e.mode in VALUE_MODES
                and not e.decision_ids and not e.rationale.strip() and not e.sources):
            finding('GAP', 'SETTING_WITHOUT_BASIS', '明示した設定値に、方針・理由・出典のいずれもありません。', item_id=item.item_id)
    kinds = Counter(f['kind'] for f in findings)
    assessment = ('CONFLICTS_FOUND' if kinds['CONFLICT'] else 'GAPS_FOUND' if kinds['GAP']
                  else 'OPEN_ITEMS' if kinds['OPEN'] else 'NO_GAPS_WITHIN_DECLARED_SCOPE')
    return {'version': '1.0', 'status': 'COMPLETE', 'assessment': assessment, 'environment_id': env,
        'outline_source': 'DECLARED' if spec.design_outline is not None else 'STANDARD',
        'summary': {'decisions': len(spec.decisions), 'links': len(links),
                    'realization': dict(sorted(Counter(d['realization'] for d in decisions).items())),
                    'mechanization': dict(sorted(Counter(d['mechanization'] for d in decisions).items())),
                    'findings': dict(sorted(kinds.items())),
                    'expansions': dict(sorted(Counter(r['result'] for r in expansion_records).items())),
                    'finding_codes': dict(sorted(Counter(f['code'] for f in findings).items()))},
        'sections': sections, 'decisions': decisions, 'links': links, 'expansions': expansion_records, 'findings': findings,
        'limitations': ['明示した decision_ids・policy_ids・applies_to だけを追跡します。方針本文の意味と設定値の妥当性は判定しません。',
                        'REALIZED は適用範囲の各リソースに方針を参照する決定済み設定があることだけを示し、方針の充足や承認を意味しません。',
                        'SETTING_WITHOUT_BASIS は上位設定のみを対象とし、AWS既定値との差異は判定しません。',
                        '展開は決定済み方針の明示した expansions だけを、未入力の上位設定に適用します。個別の設定が常に優先されます。']}


LABELS = {'DECIDED': '決定済み', 'UNDECIDED': '未決定', 'NOT_APPLICABLE': '適用外'}
REALIZATION = {'REALIZED': '具体化済み', 'PARTIAL': '一部具体化', 'NOT_REALIZED': '未具体化', 'LINKED': '設定と関連付け済み（適用範囲は未宣言）',
               'DOCUMENT_ONLY': '記述のみ（具体化の対象は未宣言）', 'NO_TARGET_IN_SCOPE': '適用範囲に該当リソースなし',
               'NOT_IN_ENVIRONMENT': 'この環境は適用範囲外', 'UNDECIDED': '方針が未決定', 'NOT_APPLICABLE': '適用外'}


def render_basic_design(document):
    """Markdown basic design generated from the same normalized document as the workbook."""
    import json
    from .document_workbook import setting as describe
    spec = document.design; env = next(e for e in spec.environments if e.id == document.environment_id)
    report = getattr(document, 'decision_trace', None) or trace(document)
    def cell(value):
        return str(value).replace('\\', '\\\\').replace('|', '\\|').replace('\r', '').replace('\n', '<br>')
    def short(value, limit=200):
        value = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
        return value if len(value) <= limit else value[:limit] + '…（全体は design.xlsx を参照）'
    def table(header, rows):
        if not rows:return ['（なし）']
        return ['| ' + ' | '.join(header) + ' |', '|' + '---|' * len(header), *['| ' + ' | '.join(cell(v) for v in row) + ' |' for row in rows]]
    requirements = {r.id: r for r in spec.requirements}
    items = {i.item_id: i for i in document.items}
    rows = {d['decision_id']: d for d in report.get('decisions', [])}
    out = [f'# {spec.system.name} 基本設計書', '',
           '> この文書は構造化入力から生成しました。修正は入力ファイルに行い、再生成してください。',
           '> 生成は設計の承認を意味しません。方針トレースは明示した関連付けだけを確認しています。', '',
           '## 文書情報', '',
           *table(['項目', '内容'], [['システム', f'{spec.system.name}（{spec.system.id}）'], ['対象環境', f'{env.name}（{env.id}）'],
                   ['リージョン', env.region], ['入力 SHA-256', document.input_sha256], ['入力版 / 共通モデル', f'{spec.schema_version} / {document.model_version}'],
                   ['方針トレース', f"{report['status']} / {report['assessment']}"], ['必要入力の充足', document.checklist.status],
                   ['案件方針', f'{document.project_policy.status} / {document.project_policy.assessment}'],
                   ['AWS静的評価', f'{document.evaluation_status} / {document.evaluation.assessment}']]), '',
           '## システム構成', '']
    if spec.system.description:out += [spec.system.description, '']
    out += ['### 環境', '', *table(['環境ID', '名前', 'リージョン', '説明'], [[e.id, e.name, e.region, e.description] for e in spec.environments]), '',
            '### 構成リソース', '', *table(['リソースID', '名前', '種類', 'リージョン', '設計理由'],
            [[r.id, r.name, r.type, document.resource_regions.get(r.id, env.region), r.rationale] for r in spec.resources]), '']
    if spec.connections:
        nodes = {r.id: f'n{i}' for i, r in enumerate(spec.resources)}
        names = {r.id: r.name for r in spec.resources}
        arrows = {'TRAFFIC': '-->', 'REFERENCE': '-.->', 'DEPENDENCY': '==>'}
        def label(value):return str(value).replace('"', "'").replace('\n', ' ')
        used = sorted({x for c in spec.connections for x in (c.source, c.target)}, key=list(nodes).index)
        out += ['### 接続', '', '```mermaid', 'flowchart LR', *[f'  {nodes[r]}["{label(names[r])}<br>{r}"]' for r in used]]
        for c in spec.connections:
            text = ' '.join(x for x in (c.kind, c.protocol, c.ports, c.property or '') if x)
            out.append(f'  {nodes[c.source]} {arrows[c.kind]}|"{label(text)}"| {nodes[c.target]}')
        out += ['```', '', '実線は通信、点線は参照、太線は依存を示します。接続可否やデプロイ順の検証結果ではありません。', '',
                *table(['接続ID', '起点 → 終点', '種別・状態', 'プロトコル・ポート', '説明・理由'],
                       [[c.id, f'{c.source} → {c.target}', f'{c.kind} / {LABELS[c.status]}', f'{c.protocol} {c.ports}'.strip(),
                         ' '.join(x for x in (c.description, c.rationale) if x)] for c in spec.connections]), '']
    for number, section in enumerate(outline(spec), 1):
        own = [d for d in spec.decisions if d.section == section.id]
        out += [f'## {number}. {section.title}', '']
        if not own:
            out += ['**未記載**（必須の章です）' if section.required else '（記載なし）', ''];continue
        for index, d in enumerate(own, 1):
            row = rows.get(d.id, {})
            out += [f'### {number}.{index} {d.title}', '', f'- 方針ID: `{d.id}`', f'- 状態: {LABELS[d.status]}', f'- 方針: {d.statement}']
            if d.rationale:out.append(f'- 理由: {d.rationale}')
            if d.alternatives:out += ['- 検討した代替案:', *[f'  - {a}' for a in d.alternatives]]
            if d.requirement_ids:out.append('- 関連要件: ' + '、'.join(f'`{r}` {requirements[r].title}' for r in d.requirement_ids))
            if d.applies_to:
                scope = d.applies_to
                parts = [*(f'`{r}`' for r in scope.resources), *(f'`{t}`' for t in scope.types)]
                out.append('- 適用範囲: ' + '、'.join(parts) + (f"（環境: {'、'.join(scope.environments)}）" if scope.environments else ''))
            out.append('- 具体化: ' + REALIZATION.get(row.get('realization'), '未確認'))
            if row.get('policy_ids'):
                results = '、'.join(f'{k}: {v}' for k, v in row['policy_results'].items()) or '判定なし'
                out.append('- 案件方針の検査: ' + '、'.join(f'`{p}`' for p in row['policy_ids']) + f'（{results}）')
            if d.expansions:
                out.append('- 展開ルール（未入力の設定にだけ適用）:')
                for e in d.expansions:
                    where = '、環境: ' + '、'.join(e.environments) if e.environments else ''
                    out.append(f"  - `{e.property}` = `{short(e.value if e.mode == 'LITERAL' else e.ref, 120)}`（{e.mode}{where}）")
            if row.get('expansion_results'):
                out.append('- 展開結果: ' + '、'.join(f'{k}: {v}' for k, v in row['expansion_results'].items()))
            if d.sources:out.append('- 出典: ' + '、'.join(d.sources))
            linked = [l for l in report.get('links', []) if l['decision_id'] == d.id]
            if linked:
                out += ['', *table(['設定ID', 'パス', '設定', '値の解決', '理由'],
                    [[l['item_id'], l['path'], short(describe(items[l['item_id']].expected) if l['path'] == '/properties/' + items[l['item_id']].name
                      else f"{LABELS[l['status']]} / {l['mode'] or '-'}"), l['value_resolution'], l['rationale']] for l in linked])]
            out.append('')
    open_rows = [[f['finding_id'], f['kind'], f['message']] for f in report.get('findings', [])]
    open_rows += [[n.id, 'ISSUE', f'{n.title}: {n.text}'] for n in spec.issues]
    appendices = [('要件一覧', table(['要件ID', '題名', '状態', '内容', '根拠にした方針'],
            [[r.id, r.title, LABELS[r.status], r.text, '、'.join(d.id for d in spec.decisions if r.id in d.requirement_ids) or '（なし）']
             for r in spec.requirements]))]
    if spec.operations:
        appendices.append(('運用・復旧', table(['項目ID', '題名', '状態', '内容'], [[o.id, o.title, LABELS[o.status], o.text] for o in spec.operations])))
    appendices += [('未決事項・方針トレースの指摘', table(['ID', '区分', '内容'], open_rows)),
                   ('出典', table(['出典ID', '名称', '参照先'], [[s.id, s.title, s.locator] for s in spec.sources]))]
    for letter, (title, body) in zip('ABCDEFG', appendices):out += [f'## 付録{letter} {title}', '', *body, '']
    return '\n'.join(out)
