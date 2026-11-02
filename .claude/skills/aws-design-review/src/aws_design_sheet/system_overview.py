"""System overview: the system to be built, above AWS resources, checked before design sheets.

An overview names requirements, actors, boundaries (account, region, environment, network,
trust), components (functions, data stores, interfaces, shared services), the flows of data
between them, quality targets (availability, RPO, RTO …) and open questions. It links down
into a 1.1 design input only through explicit IDs: a component's `realized_by` resources and
decisions, the decisions of flows and quality targets. The check reports gaps in that
understanding (requirements placed nowhere, isolated or unbounded components, missing quality
targets, boundary-crossing flows without a decision, components no resource realizes), conflicts
and open items. It does not interpret prose or infer links, and its result is not approval.
"""
import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .delegation import Basis, InputError as DelegationError, is_agent, person_name

ID = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_-]{0,63}$')]
Status = Literal['DECIDED', 'UNDECIDED', 'NOT_APPLICABLE']
ATTRIBUTES = ('AVAILABILITY', 'RPO', 'RTO', 'PERFORMANCE', 'CAPACITY', 'RETENTION', 'SECURITY', 'COMPLIANCE', 'COST', 'OTHER')
ATTRIBUTES_JA = {'AVAILABILITY': '可用性', 'RPO': 'RPO', 'RTO': 'RTO', 'PERFORMANCE': '性能', 'CAPACITY': '容量', 'RETENTION': '保持期間',
                 'SECURITY': 'セキュリティ', 'COMPLIANCE': '準拠', 'COST': 'コスト', 'OTHER': 'その他'}
FINDINGS_JA = {
    'REQUIREMENT_NOT_PLACED': '要件がどの構成要素・流れ・目標値にも結び付いていない',
    'REQUIREMENT_FROM_OLD_DOCUMENT': '要件の根拠が文書セットの旧版・対象外・変更後の文書だけ',
    'REQUIREMENT_NOT_APPROVED_IN_ARP': '要件がARP4の正本で未承認',
    'COMPONENT_WITHOUT_REQUIREMENT': '構成要素に根拠となる要件がない',
    'COMPONENT_WITHOUT_BOUNDARY': '構成要素の配置境界（アカウント・リージョン・ネットワークなど）がない',
    'COMPONENT_WITHOUT_FLOW': '構成要素がどの流れにも現れない',
    'QUALITY_TARGET_MISSING': '必要な非機能の目標値がない',
    'BOUNDARY_FLOW_WITHOUT_DECISION': '境界をまたぐ流れに方針（認証・暗号化・経路など）がない',
    'COMPONENT_NOT_REALIZED': '構成要素を具体化するリソースがない',
    'QUALITY_TARGET_WITHOUT_DECISION': '非機能の目標値を実現する方針がない',
    'REQUIREMENT_NOT_IN_DESIGN': '概要の要件が設計入力にない',
    'RESOURCE_NOT_IN_OVERVIEW': '設計入力のリソースがどの構成要素にも属さない',
    'UNKNOWN_DESIGN_REFERENCE': '概要が参照するリソース・方針が設計入力にない',
    'REQUIREMENT_TEXT_DIFFERS': '同じIDの要件の本文が概要と設計入力で違う',
    'ITEM_UNDECIDED': '未決定の項目',
    'ELEMENT_WITHOUT_REQUIREMENT': '作成担当が書いた要素に根拠の要件がない',
    'OPEN_QUESTION': '未決事項',
}
CATEGORY = {code: 'CONFLICT' for code in ('REQUIREMENT_FROM_OLD_DOCUMENT', 'UNKNOWN_DESIGN_REFERENCE', 'REQUIREMENT_TEXT_DIFFERS')}
CATEGORY.update({code: 'OPEN' for code in ('REQUIREMENT_NOT_APPROVED_IN_ARP', 'ITEM_UNDECIDED', 'OPEN_QUESTION')})


class InputError(ValueError):
    pass


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


class System(Strict):
    id: ID
    name: str = Field(min_length=1)
    purpose: str = ''


class ArpOrigin(Strict):
    id: str
    category: str
    module: str = ''
    approval: str = 'proposed'
    documents: list[str] = Field(default_factory=list)
    basis: Literal['CURRENT', 'REFERENCE_ONLY', 'OLD_DOCUMENT', 'NOT_IN_SOURCE_SET', 'NOT_CHECKED', 'NO_EVIDENCE'] = 'NOT_CHECKED'
    statement_sha256: str = ''


class Requirement(Strict):
    id: ID
    title: str = Field(min_length=1)
    text: str = ''
    kind: Literal['FUNCTIONAL', 'NON_FUNCTIONAL', 'CONSTRAINT', 'UNCLASSIFIED'] = 'UNCLASSIFIED'
    status: Status = 'DECIDED'
    sources: list[str] = Field(default_factory=list)
    arp: ArpOrigin | None = None


class Actor(Strict):
    id: ID
    name: str = Field(min_length=1)
    kind: Literal['USER', 'OPERATOR', 'EXTERNAL_SYSTEM'] = 'USER'
    description: str = ''
    requirement_ids: list[ID] = Field(default_factory=list)


class Boundary(Strict):
    id: ID
    name: str = Field(min_length=1)
    kind: Literal['ACCOUNT', 'REGION', 'ENVIRONMENT', 'NETWORK', 'TRUST', 'OTHER'] = 'OTHER'
    parent: ID | None = None


class Realization(Strict):
    resources: list[ID] = Field(default_factory=list)
    decisions: list[ID] = Field(default_factory=list)


class Component(Strict):
    id: ID
    name: str = Field(min_length=1)
    kind: Literal['FUNCTION', 'DATA_STORE', 'INTERFACE', 'SHARED_SERVICE', 'OPERATIONS'] = 'FUNCTION'
    description: str = ''
    boundary: ID | None = None
    requirement_ids: list[ID] = Field(default_factory=list)
    status: Status = 'DECIDED'
    realized_by: Realization = Field(default_factory=Realization)


class Flow(Strict):
    id: ID
    source: ID
    target: ID
    data: str = Field(min_length=1)
    protocol: str = ''
    requirement_ids: list[ID] = Field(default_factory=list)
    decision_ids: list[ID] = Field(default_factory=list)
    status: Status = 'DECIDED'


class QualityTarget(Strict):
    id: ID
    attribute: Literal[ATTRIBUTES]
    target: str = Field(min_length=1)
    applies_to: list[ID] = Field(default_factory=list)
    requirement_ids: list[ID] = Field(default_factory=list)
    decision_ids: list[ID] = Field(default_factory=list)
    status: Status = 'DECIDED'


class OpenQuestion(Strict):
    id: ID
    text: str = Field(min_length=1)
    about: list[ID] = Field(default_factory=list)
    owner: str = ''
    answer: str = ''
    answered_by: str = ''


class Author(Strict):
    actor: str = Field(min_length=1)
    model: str = ''


class Overview(Strict):
    schema_version: Literal['1']
    # Set by a drafting agent: its elements must then cite requirements, and an independent review precedes agreement.
    author: Author | None = None
    system: System
    required_attributes: list[Literal[ATTRIBUTES]] = Field(default_factory=lambda: ['AVAILABILITY', 'RPO', 'RTO'])
    requirements: list[Requirement] = Field(default_factory=list)
    actors: list[Actor] = Field(default_factory=list)
    boundaries: list[Boundary] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    flows: list[Flow] = Field(default_factory=list)
    quality_targets: list[QualityTarget] = Field(default_factory=list)
    open_questions: list[OpenQuestion] = Field(default_factory=list)


class OverviewReview(Strict):
    version: Literal['1']
    overview_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    decision: Literal['accepted', 'rejected']
    actor: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    recorded_at: str
    author: str | None = None
    findings: dict[str, int] = Field(default_factory=dict)


class OverviewApproval(Strict):
    version: Literal['1']
    overview_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    approver: str = Field(min_length=1)
    approved_at: str
    assessment: str
    accepted_findings: dict[str, int] = Field(default_factory=dict)
    # Set only when an agent agreed under a delegation policy.
    delegation: Basis | None = None


def load(raw):
    """An overview from JSON or YAML bytes, with every internal reference resolved."""
    import yaml
    data = yaml.safe_load(raw)
    overview = Overview.model_validate(data)
    collections = (overview.requirements, overview.actors, overview.boundaries, overview.components, overview.flows,
                   overview.quality_targets, overview.open_questions)
    ids = [x.id for c in collections for x in c]
    duplicates = sorted(i for i, n in Counter(ids).items() if n > 1)
    if duplicates:raise InputError('DUPLICATE_ID: ' + ', '.join(duplicates))
    requirements = {r.id for r in overview.requirements}
    boundaries = {b.id for b in overview.boundaries}
    nodes = {a.id for a in overview.actors} | {c.id for c in overview.components}
    unknown = []
    for item in [*overview.actors, *overview.components, *overview.flows, *overview.quality_targets]:
        unknown += [f'{item.id}→{r}' for r in item.requirement_ids if r not in requirements]
    unknown += [f'{b.id}→{b.parent}' for b in overview.boundaries if b.parent and b.parent not in boundaries]
    unknown += [f'{c.id}→{c.boundary}' for c in overview.components if c.boundary and c.boundary not in boundaries]
    unknown += [f'{f.id}→{e}' for f in overview.flows for e in (f.source, f.target) if e not in nodes]
    unknown += [f'{t.id}→{c}' for t in overview.quality_targets for c in t.applies_to if c not in {x.id for x in overview.components}]
    unknown += [f'{q.id}→{a}' for q in overview.open_questions for a in q.about if a not in set(ids)]
    if unknown:raise InputError('UNKNOWN_REFERENCE: ' + ', '.join(unknown))
    for b in overview.boundaries:
        chain, at = set(), b
        while at.parent:
            if at.id in chain:raise InputError(f'BOUNDARY_CYCLE: {b.id}')
            chain.add(at.id);at = next(x for x in overview.boundaries if x.id == at.parent)
    return overview


def boundary_path(overview, boundary_id):
    """A boundary and its ancestors, innermost first."""
    path, at = [], boundary_id
    by_id = {b.id: b for b in overview.boundaries}
    while at:
        path.append(at);at = by_id[at].parent
    return path


def check(overview, design=None):
    """Findings about the understanding of the system; with a 1.1 input, also about its realization."""
    findings = []

    def add(code, target, detail=''):
        findings.append({'category': CATEGORY.get(code, 'GAP'), 'code': code, 'target': target, 'detail': detail, 'meaning': FINDINGS_JA[code]})
    decided = lambda x: x.status == 'DECIDED'
    placed = {r for item in [*overview.actors, *overview.components, *overview.flows, *overview.quality_targets] for r in item.requirement_ids}
    for r in overview.requirements:
        if decided(r) and r.id not in placed:add('REQUIREMENT_NOT_PLACED', r.id)
        if r.arp and r.arp.basis == 'OLD_DOCUMENT':add('REQUIREMENT_FROM_OLD_DOCUMENT', r.id, '、'.join(r.arp.documents))
        if r.arp and r.arp.approval != 'approved':add('REQUIREMENT_NOT_APPROVED_IN_ARP', r.id, r.arp.id)
    in_flow = {e for f in overview.flows for e in (f.source, f.target)}
    for c in overview.components:
        if not decided(c):continue
        if not c.requirement_ids:add('COMPONENT_WITHOUT_REQUIREMENT', c.id)
        if not c.boundary:add('COMPONENT_WITHOUT_BOUNDARY', c.id)
        if c.id not in in_flow:add('COMPONENT_WITHOUT_FLOW', c.id)
    declared = {t.attribute for t in overview.quality_targets if t.status != 'NOT_APPLICABLE'}
    for attribute in overview.required_attributes:
        if attribute not in declared:add('QUALITY_TARGET_MISSING', attribute, ATTRIBUTES_JA[attribute])
    components = {c.id: c for c in overview.components}

    def outer(node):
        component = components.get(node)
        return frozenset(boundary_path(overview, component.boundary)) if component and component.boundary else frozenset()
    for f in overview.flows:
        if decided(f) and outer(f.source) != outer(f.target) and not f.decision_ids:
            add('BOUNDARY_FLOW_WITHOUT_DECISION', f.id, f'{f.source} → {f.target}')
    if overview.author is not None:
        for item in [*overview.actors, *overview.flows, *overview.quality_targets]:
            if getattr(item, 'status', 'DECIDED') == 'DECIDED' and not item.requirement_ids:add('ELEMENT_WITHOUT_REQUIREMENT', item.id)
    for item in [*overview.requirements, *overview.components, *overview.flows, *overview.quality_targets]:
        if item.status == 'UNDECIDED':add('ITEM_UNDECIDED', item.id)
    for q in overview.open_questions:
        if not q.answer:add('OPEN_QUESTION', q.id, q.text)
    if design is not None:
        resources = {r.get('id') for r in design.get('resources', []) if isinstance(r, dict)}
        decisions = {d.get('id') for d in design.get('decisions', []) if isinstance(d, dict)}
        design_requirements = {r.get('id'): r for r in design.get('requirements', []) if isinstance(r, dict)}
        for c in overview.components:
            missing = [r for r in c.realized_by.resources if r not in resources] + [d for d in c.realized_by.decisions if d not in decisions]
            if missing:add('UNKNOWN_DESIGN_REFERENCE', c.id, '、'.join(missing))
            if decided(c) and c.kind != 'OPERATIONS' and not [r for r in c.realized_by.resources if r in resources]:add('COMPONENT_NOT_REALIZED', c.id)
        for item in [*overview.flows, *overview.quality_targets]:
            missing = [d for d in item.decision_ids if d not in decisions]
            if missing:add('UNKNOWN_DESIGN_REFERENCE', item.id, '、'.join(missing))
        for t in overview.quality_targets:
            if decided(t) and not t.decision_ids:add('QUALITY_TARGET_WITHOUT_DECISION', t.id, ATTRIBUTES_JA[t.attribute])
        for r in overview.requirements:
            if not decided(r):continue
            if r.id not in design_requirements:add('REQUIREMENT_NOT_IN_DESIGN', r.id)
            elif r.text and str(design_requirements[r.id].get('text', '')).strip() != r.text.strip():add('REQUIREMENT_TEXT_DIFFERS', r.id)
        realized = {x for c in overview.components for x in c.realized_by.resources}
        for resource_id in sorted(resources - realized):add('RESOURCE_NOT_IN_OVERVIEW', resource_id)
    counts = Counter(f['category'] for f in findings)
    assessment = ('CONFLICTS_FOUND' if counts['CONFLICT'] else 'GAPS_FOUND' if counts['GAP'] else
                  'OPEN_ITEMS' if counts['OPEN'] else 'NO_GAPS_WITHIN_DECLARED_SCOPE')
    return {'version': '1', 'system': overview.system.id, 'assessment': assessment, 'design_checked': design is not None,
            'summary': {'requirements': len(overview.requirements), 'actors': len(overview.actors), 'boundaries': len(overview.boundaries),
                        'components': len(overview.components), 'flows': len(overview.flows), 'quality_targets': len(overview.quality_targets),
                        'open_questions': len(overview.open_questions), 'findings': dict(sorted(counts.items())),
                        'codes': dict(sorted(Counter(f['code'] for f in findings).items()))},
            'findings': findings, 'trace': trace(overview),
            'open_questions': [{'id': q.id, 'owner': q.owner, 'answered': bool(q.answer)} for q in overview.open_questions],
            'limitations': ['明示したIDの対応だけを見る。本文の意味や対応の正しさは判定しない。', '検査結果は理解の穴の目安であり、承認ではない。']}


def trace(overview):
    """Requirement → where it is placed → which decisions and resources realize it."""
    rows = []
    for r in overview.requirements:
        components = [c for c in overview.components if r.id in c.requirement_ids]
        flows = [f.id for f in overview.flows if r.id in f.requirement_ids]
        targets = [t for t in overview.quality_targets if r.id in t.requirement_ids]
        decisions = sorted({d for c in components for d in c.realized_by.decisions} | {d for t in targets for d in t.decision_ids}
                           | {d for f in overview.flows if r.id in f.requirement_ids for d in f.decision_ids})
        rows.append({'requirement': r.id, 'components': [c.id for c in components], 'flows': flows, 'quality_targets': [t.id for t in targets],
                     'decisions': decisions, 'resources': sorted({x for c in components for x in c.realized_by.resources})})
    return rows


def node(text):
    # A prefix keeps IDs such as end or graph from reading as Mermaid keywords.
    return 'n_' + text.replace('-', '_')


def label(text):return str(text).replace('"', "'").replace('\n', ' ')


def diagram(overview):
    lines = ['```mermaid', 'flowchart LR']
    children = {}
    for b in overview.boundaries:children.setdefault(b.parent, []).append(b)
    members = {}
    for c in overview.components:members.setdefault(c.boundary, []).append(c)
    shape = {'DATA_STORE': ('[(', ')]'), 'INTERFACE': ('([', '])'), 'SHARED_SERVICE': ('[[', ']]'), 'OPERATIONS': ('[/', '/]')}

    def emit(boundary, depth):
        pad = '  ' * depth
        lines.append(f'{pad}subgraph {node(boundary.id)}["{label(boundary.name)}"]')
        for child in children.get(boundary.id, []):emit(child, depth + 1)
        for c in members.get(boundary.id, []):
            left, right = shape.get(c.kind, ('[', ']'))
            lines.append(f'{pad}  {node(c.id)}{left}"{label(c.name)}"{right}')
        lines.append(f'{pad}end')
    for b in children.get(None, []):emit(b, 1)
    for c in members.get(None, []):
        left, right = shape.get(c.kind, ('[', ']'))
        lines.append(f'  {node(c.id)}{left}"{label(c.name)}"{right}')
    for a in overview.actors:lines.append(f'  {node(a.id)}(("{label(a.name)}"))')
    for f in overview.flows:
        arrow = '-.->' if f.status != 'DECIDED' else '-->'
        lines.append(f'  {node(f.source)} {arrow}|"{label(f.data)}"| {node(f.target)}')
    lines.append('```')
    return lines


def render(overview, report):
    s = report['summary']
    lines = [f'# システム概要：{overview.system.name}', '']
    if overview.system.purpose:lines += [overview.system.purpose, '']
    lines += [f"要件 {s['requirements']}・利用者と外部システム {s['actors']}・境界 {s['boundaries']}・構成要素 {s['components']}・"
              f"流れ {s['flows']}・非機能の目標値 {s['quality_targets']}・未決事項 {s['open_questions']}。判定 {report['assessment']}"
              + ('（設計入力と照合）' if report['design_checked'] else '（設計入力との照合なし）') + '。', '']
    lines += ['## 全体図', ''] + diagram(overview) + ['', '実線は決定済み、点線は未決定の流れ。', '']
    findings = [f for f in report['findings'] if f['category'] in ('CONFLICT', 'GAP')]
    lines += [f'## 理解の穴と矛盾（{len(findings)}件）', '']
    if findings:
        lines += ['| 区分 | 対象 | 内容 | 補足 |', '|---|---|---|---|']
        lines += [f"| {f['category']} | {f['target']} | {f['meaning']} | {label(f['detail']) or '—'} |" for f in findings]
    else:lines.append('なし。')
    lines += ['', '## 構成要素', '', '| 構成要素 | 種類 | 境界 | 要件 | 具体化するリソース | 方針 |', '|---|---|---|---|---|---|']
    names = {b.id: b.name for b in overview.boundaries}
    for c in overview.components:
        lines.append(f"| {c.name}（{c.id}） | {c.kind} | {names.get(c.boundary, '—')} | {'、'.join(c.requirement_ids) or '—'} | "
                     f"{'、'.join(c.realized_by.resources) or '—'} | {'、'.join(c.realized_by.decisions) or '—'} |")
    lines += ['', '## 非機能の目標値', '']
    if overview.quality_targets:
        lines += ['| 属性 | 目標 | 対象 | 方針 | 状態 |', '|---|---|---|---|---|']
        lines += [f"| {ATTRIBUTES_JA[t.attribute]} | {label(t.target)} | {'、'.join(t.applies_to) or '全体'} | {'、'.join(t.decision_ids) or '—'} | {t.status} |"
                  for t in overview.quality_targets]
    else:lines.append('なし。')
    lines += ['', '## 要件の追跡', '', '| 要件 | 構成要素 | 流れ | 目標値 | 方針 | リソース |', '|---|---|---|---|---|---|']
    titles = {r.id: r.title for r in overview.requirements}
    lines += [f"| {titles[t['requirement']]}（{t['requirement']}） | {'、'.join(t['components']) or '—'} | {'、'.join(t['flows']) or '—'} | "
              f"{'、'.join(t['quality_targets']) or '—'} | {'、'.join(t['decisions']) or '—'} | {'、'.join(t['resources']) or '—'} |" for t in report['trace']]
    open_items = [f for f in report['findings'] if f['category'] == 'OPEN']
    lines += ['', f'## 未決定・未決事項（{len(open_items)}件）', '']
    lines += [f"- {f['target']}：{f['meaning']}" + (f"（{label(f['detail'])}）" if f['detail'] else '') for f in open_items] or ['なし。']
    lines += ['', '---', ''] + report['limitations']
    return '\n'.join(lines) + '\n'


def sha(raw):return hashlib.sha256(raw).hexdigest()


def read_registry(arp_root, categories=('requirement',)):
    """ARP4 registry records of the given categories, with the documents and extraction revisions their evidence quotes."""
    base = Path(arp_root) / '.arp' / 'registry'
    if not (base / 'registry.json').is_file():raise InputError('NO_ARP_REGISTRY: .arp/registry/registry.json not found below the ARP root')
    manifest = json.loads((base / 'registry.json').read_text(encoding='utf-8'))
    snapshots = {}
    records = []
    for record_id in sorted(manifest.get('records', {})):
        record = json.loads((base / 'records' / f'{record_id}.json').read_text(encoding='utf-8'))
        if record.get('category') not in categories:continue
        quoted = {}
        for evidence in record.get('evidence', []):
            snapshot = evidence.get('snapshot')
            if snapshot not in snapshots:
                path = base / 'evidence' / f'{snapshot}.json'
                snapshots[snapshot] = json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {}
            data = snapshots[snapshot]
            source = next((s for s in data.get('sources', []) if s.get('id') == (evidence.get('span') or {}).get('source')), None)
            if source:quoted[source['document']] = data.get('revisions', {}).get(source['document'])
        records.append({'record': record, 'documents': quoted})
    return records


def basis(documents, entries):
    """How a requirement's evidence stands against an approved source set."""
    if not documents:return 'NO_EVIDENCE'
    if entries is None:return 'NOT_CHECKED'
    states = []
    for document, revision in documents.items():
        entry = entries.get(document)
        if entry is None:states.append('NOT_IN_SOURCE_SET')
        elif entry.extraction_sha256 != revision or entry.status in ('SUPERSEDED', 'EXCLUDED'):states.append('OLD_DOCUMENT')
        else:states.append('CURRENT' if entry.status == 'CURRENT' else 'REFERENCE_ONLY')
    for state in ('CURRENT', 'REFERENCE_ONLY', 'OLD_DOCUMENT'):
        if state in states:return state
    return 'NOT_IN_SOURCE_SET'


def requirement_from(item, entries):
    record = item['record']
    statement = str(record.get('statement') or record.get('name') or '')
    approval = 'approved' if record.get('status') == 'approved' else str(record.get('status', 'proposed'))
    return Requirement(id=record['id'].lower(), title=str(record.get('name') or record['id']), text=statement, sources=sorted(item['documents']),
                       arp=ArpOrigin(id=record['id'], category=record.get('category', ''), module=str(record.get('module') or ''), approval=approval,
                                     documents=sorted(item['documents']), basis=basis(item['documents'], entries),
                                     statement_sha256=hashlib.sha256(statement.encode('utf-8')).hexdigest()))


def source_entries(set_raw):
    if set_raw is None:return None
    from .source_set import load_approved
    return {e.document_id: e for e in load_approved(set_raw).documents}


def from_registry(arp_root, set_raw=None, categories=('requirement',)):
    """Requirements of the ARP4 registry for an overview; retired records stay out."""
    entries = source_entries(set_raw)
    items = read_registry(arp_root, categories)
    found = [requirement_from(item, entries) for item in items if item['record'].get('status') != 'retired']
    return found, sorted(i['record']['id'].lower() for i in items if i['record'].get('status') == 'retired')


def template_skeleton(name, library=None):
    """A typical shape to start from. Every component, flow and quality target in it is UNDECIDED, so it claims nothing."""
    from .library import find
    data = json.loads(find('overview-templates', name, library).read_text(encoding='utf-8'))
    for key in ('components', 'flows', 'quality_targets'):
        for item in data.get(key, []):item['status'] = 'UNDECIDED';item['requirement_ids'] = []
    for item in data.get('actors', []):item['requirement_ids'] = []
    return {k: data.get(k, []) for k in ('actors', 'boundaries', 'components', 'flows', 'quality_targets', 'open_questions')}


def init(system_id, name, arp_root, set_raw=None, categories=('requirement',), template=None, library=None):
    requirements, _ = from_registry(arp_root, set_raw, categories) if arp_root else ([], [])
    overview = Overview(schema_version='1', system=System(id=system_id, name=name), requirements=requirements,
                        **(template_skeleton(template, library) if template else {}))
    return overview, {'requirements': len(requirements), 'basis': dict(sorted(Counter(r.arp.basis for r in requirements).items()))}


def sync(overview, arp_root, set_raw=None, categories=('requirement',)):
    """Refresh ARP-sourced requirements. Kinds set by people are kept; retired or vanished ones stay as NOT_APPLICABLE so links remain readable."""
    fresh, retired = from_registry(arp_root, set_raw, categories)
    fresh = {r.id: r for r in fresh}
    report = {'added': [], 'changed': [], 'retired': [], 'unchanged': 0}
    kept = []
    for r in overview.requirements:
        if r.arp is None:kept.append(r);continue
        new = fresh.pop(r.id, None)
        if new is None:
            if r.status != 'NOT_APPLICABLE':report['retired'].append(r.id)
            kept.append(r.model_copy(update={'status': 'NOT_APPLICABLE'}))
            continue
        new = new.model_copy(update={'kind': r.kind, 'status': r.status if r.status != 'NOT_APPLICABLE' else 'DECIDED'})
        if new.arp.statement_sha256 != r.arp.statement_sha256:report['changed'].append(r.id)
        else:report['unchanged'] += 1
        kept.append(new)
    for r in fresh.values():
        report['added'].append(r.id);kept.append(r)
    return overview.model_copy(update={'requirements': kept}), report


def design_requirements(overview, design):
    """A 1.1 input with the overview's decided requirements added; existing requirements are never overwritten."""
    design = json.loads(json.dumps(design))
    existing = {r.get('id'): r for r in design.get('requirements', []) if isinstance(r, dict)}
    sources = design.setdefault('sources', [])
    by_locator = {s.get('locator'): s.get('id') for s in sources if isinstance(s, dict)}
    used = {s.get('id') for s in sources if isinstance(s, dict)}
    report = {'added': [], 'differs': [], 'already_present': 0}
    for r in overview.requirements:
        if r.status != 'DECIDED':continue
        if r.id in existing:
            if r.text and str(existing[r.id].get('text', '')).strip() != r.text.strip():report['differs'].append(r.id)
            else:report['already_present'] += 1
            continue
        ids = []
        for document in r.sources:
            if document not in by_locator:
                source_id = 'doc-' + hashlib.sha256(document.encode('utf-8')).hexdigest()[:12]
                if source_id not in used:sources.append({'id': source_id, 'title': document, 'locator': document});used.add(source_id)
                by_locator[document] = source_id
            ids.append(by_locator[document])
        design.setdefault('requirements', []).append({'id': r.id, 'title': r.title, 'text': r.text or r.title, 'sources': sorted(set(ids))})
        report['added'].append(r.id)
    return design, report


def plain(text):
    import unicodedata
    return ''.join(unicodedata.normalize('NFKC', str(text)).lower().split())


def placements(overview):
    """Where each requirement is placed, in terms independent of the IDs an author chose."""
    out = {r.id: set() for r in overview.requirements}
    boundaries = {b.id: b for b in overview.boundaries}
    for c in overview.components:
        where = boundaries[c.boundary].kind if c.boundary else 'NONE'
        for r in c.requirement_ids:out.setdefault(r, set()).add(f'構成要素:{c.kind}@{where}')
    for a in overview.actors:
        for r in a.requirement_ids:out.setdefault(r, set()).add(f'利用者:{a.kind}')
    for f in overview.flows:
        for r in f.requirement_ids:out.setdefault(r, set()).add('流れ' + ('（方針あり）' if f.decision_ids else ''))
    for q in overview.quality_targets:
        for r in q.requirement_ids:out.setdefault(r, set()).add(f'目標値:{q.attribute}')
    return out


def compare(first, second):
    """Two independent drafts: requirements placed differently, quality targets, boundaries and actors that differ."""
    if first.author and second.author and first.author.actor.strip() == second.author.actor.strip():
        raise InputError('SAME_AUTHOR: compare drafts by two different actors')
    a, b = placements(first), placements(second)
    requirements = sorted(set(a) | set(b))
    placed = [{'requirement': r, 'first': sorted(a.get(r, ())), 'second': sorted(b.get(r, ()))} for r in requirements if a.get(r, set()) != b.get(r, set())]
    targets = lambda o: {q.attribute: plain(q.target) for q in o.quality_targets if q.status == 'DECIDED'}
    ta, tb = targets(first), targets(second)
    target_diffs = [{'attribute': k, 'first': ta.get(k), 'second': tb.get(k)} for k in sorted(set(ta) | set(tb)) if ta.get(k) != tb.get(k)]
    named = lambda items: {(x.kind, plain(x.name)) for x in items}
    return {'status': 'AGREE' if not (placed or target_diffs or named(first.boundaries) ^ named(second.boundaries) or named(first.actors) ^ named(second.actors))
            else 'DISAGREE',
            'actors': [first.author.actor if first.author else None, second.author.actor if second.author else None],
            'requirements_compared': len(requirements), 'requirement_differences': placed,
            'agreement_rate': round(1 - len(placed) / len(requirements), 4) if requirements else 1.0,
            'quality_target_differences': target_diffs,
            'boundary_differences': {'first_only': sorted(map(list, named(first.boundaries) - named(second.boundaries))),
                                     'second_only': sorted(map(list, named(second.boundaries) - named(first.boundaries)))},
            'actor_differences': {'first_only': sorted(map(list, named(first.actors) - named(second.actors))),
                                  'second_only': sorted(map(list, named(second.actors) - named(first.actors)))}}


def review(raw, decision, actor, reason, *, now=None):
    """An independent reviewer's record for a drafted overview, bound to its hash; never the author."""
    overview = load(raw)
    if not actor.strip() or not reason.strip():raise InputError('ACTOR_AND_REASON_REQUIRED')
    if overview.author and overview.author.actor.strip() == actor.strip():raise InputError('REVIEWER_IS_AUTHOR: use an independent reviewer')
    report = check(overview)
    if decision == 'accepted' and report['assessment'] == 'CONFLICTS_FOUND':raise InputError('CONFLICTS_FOUND: a draft with conflicts cannot be accepted')
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    return OverviewReview(version='1', overview_sha256=sha(raw), decision=decision, actor=actor.strip(), reason=reason.strip(), recorded_at=stamp,
                          author=overview.author.actor if overview.author else None, findings=report['summary']['codes']).model_dump()


def approve(raw, approver, *, now=None, delegation=None):
    """Record that a named person agreed this overview; conflicts must be resolved first, gaps and open items are listed.

    An agent agrees only with a delegation basis, under an agent name."""
    if delegation is None:
        try:approver = person_name(approver)
        except DelegationError as exc:raise InputError(str(exc)) from None
    elif not is_agent(approver):raise InputError('DELEGATED_APPROVAL: an agent agrees under an agent name')
    report = check(load(raw))
    conflicts = [f for f in report['findings'] if f['category'] == 'CONFLICT']
    if conflicts:raise InputError('CONFLICTS_FOUND: ' + ', '.join(f"{f['code']} {f['target']}" for f in conflicts))
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    return OverviewApproval(version='1', overview_sha256=sha(raw), approver=approver.strip(), approved_at=stamp, assessment=report['assessment'],
                            accepted_findings=report['summary']['codes'], delegation=delegation).model_dump(exclude_none=True)


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design system', description='System overview above AWS resources: check, draw and agree it before design sheets')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('schema', help='JSON Schema of the overview')
    p = sub.add_parser('check', help='check an overview and write system-overview.md');p.add_argument('overview')
    p.add_argument('--design', help='1.1 design input to check realization against');p.add_argument('--output', help='fresh directory for the Markdown and JSON')
    p = sub.add_parser('compare', help='two independent drafts: where they place requirements differently');p.add_argument('first');p.add_argument('second')
    p = sub.add_parser('review', help='record an independent review of a drafted overview');p.add_argument('overview')
    p.add_argument('--decision', choices=['accepted', 'rejected'], required=True);p.add_argument('--actor', required=True)
    p.add_argument('--reason', required=True);p.add_argument('--output', required=True)
    p = sub.add_parser('approve', help='record agreement by a person the user names');p.add_argument('overview')
    p.add_argument('--approver', required=True);p.add_argument('--output', required=True)
    def arp_args(p, required=True):
        p.add_argument('--arp-root', required=required);p.add_argument('--source-set', help='approved aws-design sources set to judge each requirement\'s evidence')
        p.add_argument('--category', action='append', help='ARP4 categories to take (default: requirement)')
    p = sub.add_parser('init', help='new overview with the requirements of an ARP4 registry and, optionally, a template shape');arp_args(p, required=False)
    p.add_argument('--template', help='overview template name or path (UNDECIDED shape to start from)');p.add_argument('--library', help='organisation library folder')
    p.add_argument('--system-id', required=True);p.add_argument('--name', required=True);p.add_argument('--output', required=True)
    p = sub.add_parser('sync', help='refresh the ARP4 requirements of an overview into a new file');p.add_argument('overview');arp_args(p)
    p.add_argument('--output', required=True)
    p = sub.add_parser('design-requirements', help='add the overview requirements to a copy of a 1.1 input');p.add_argument('overview')
    p.add_argument('--input', required=True);p.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'schema':
            print(json.dumps(Overview.model_json_schema(), ensure_ascii=False, indent=2));return 0
        if args.command in ('init', 'sync', 'design-requirements'):
            output = Path(args.output)
            if output.exists():raise InputError('output already exists; use a fresh path')
            if args.command == 'design-requirements':
                import yaml
                design, report = design_requirements(load(Path(args.overview).read_bytes()), yaml.safe_load(Path(args.input).read_bytes()))
                result = design
            else:
                set_raw = Path(args.source_set).read_bytes() if args.source_set else None
                categories = tuple(args.category or ['requirement'])
                if args.command == 'init':
                    if not args.arp_root and not args.template:raise InputError('init needs --arp-root, --template or both')
                    result, report = init(args.system_id, args.name, args.arp_root, set_raw, categories, args.template, args.library)
                else:result, report = sync(load(Path(args.overview).read_bytes()), args.arp_root, set_raw, categories)
                result = result.model_dump(exclude_none=True)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            print(json.dumps({'output': str(output), **report}, ensure_ascii=False));return 0
        if args.command == 'compare':
            report = compare(load(Path(args.first).read_bytes()), load(Path(args.second).read_bytes()))
            print(json.dumps(report, ensure_ascii=False, indent=2));return 0 if report['status'] == 'AGREE' else 3
        raw = Path(args.overview).read_bytes()
        if args.command == 'review':
            output = Path(args.output)
            if output.exists():raise InputError('output already exists; use a fresh path')
            record = review(raw, args.decision, args.actor, args.reason)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            print(json.dumps({'review': record['decision'], 'overview_sha256': record['overview_sha256']}, ensure_ascii=False));return 0
        if args.command == 'approve':
            output = Path(args.output)
            if output.exists():raise InputError('output already exists; use a fresh path')
            record = approve(raw, args.approver)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            print(json.dumps({'approval': str(output), 'assessment': record['assessment']}, ensure_ascii=False));return 0
        import yaml
        overview = load(raw)
        design = yaml.safe_load(Path(args.design).read_bytes()) if args.design else None
        report = check(overview, design)
        if args.output:
            out = Path(args.output)
            if out.exists():raise InputError('output directory already exists; use a fresh destination')
            out.mkdir(parents=True)
            (out / 'system-overview.md').write_text(render(overview, report), encoding='utf-8')
            (out / 'system-overview-check.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'assessment': report['assessment'], 'findings': report['summary']['findings'], 'codes': report['summary']['codes']},
                         ensure_ascii=False));return 0
    except ValidationError as exc:
        errors = [{'loc': [str(x) for x in e['loc']], 'type': e['type']} for e in exc.errors(include_input=False, include_context=False)]
        print(json.dumps({'status': 'ERROR', 'message': 'CONTRACT_INVALID', 'errors': errors}, ensure_ascii=False));return 2
    except (InputError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc) if isinstance(exc, InputError) else type(exc).__name__}, ensure_ascii=False));return 2
    except ValueError as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc)[:300]}, ensure_ascii=False));return 2


if __name__ == '__main__':
    raise SystemExit(main())
