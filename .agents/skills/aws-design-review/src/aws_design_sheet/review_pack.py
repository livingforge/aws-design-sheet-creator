"""Review pack: one place for the reviewer, ordered by what needs a person.

Each generated value gets a provenance tier from what is known about how it was made
(an approved dictionary mapping as written, a converted mapping, a decision expansion,
a default or sourceless value, a value the grounding check found in the cells it cites, or
an interpretation). Priorities combine the tier with missing or undecided inputs, flags,
findings and stale values. Rows that need a person come in the order of who settles them: the
decisions people answer, other gaps and findings, the designer's own tasks, then build-time
notes; interpretations come before values found in their cells. Rows a reviewer marked OK
leave the pack while their fingerprint is unchanged. The pack orders review work; it is
not an approval.
"""
import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .collection_matrix import open_path_text
from .delegation import Basis, InputError as DelegationError, person_name

TIERS = {'TRANSCRIBED': '機械転記', 'CONVERTED': '辞書変換', 'DECISION': '方針から展開', 'CITED': 'セルに記載', 'INTERPRETED': '解釈',
         'ASSUMED': '推定・既定'}
PRIORITIES = {'P1': '判断が必要', 'P2': '解釈の確認', 'P3': '抜取り確認', 'P4': '確認不要', 'DONE': '前回確認済み（変更なし）'}
TIER_PRIORITY = {'ASSUMED': 'P1', 'INTERPRETED': 'P2', 'DECISION': 'P2', 'CITED': 'P2', 'CONVERTED': 'P3', 'TRANSCRIBED': 'P4'}
# Who settles an open value, in the order P1 rows are listed; rows without a cause sit between asks and the designer's tasks.
CAUSE_GROUPS = {'OWNER_DECISION': (0, '人の判断'), 'WAITS_FOR': (0, '人の判断'), 'EXTERNAL_DATA': (0, '人の判断'),
                'DESIGNER_TASK': (2, '設計者の宿題'), 'BUILD_NOTE': (3, '構築時の注意')}
# Within P2, interpretations are read before values the grounding check found in their cells.
TIER_ORDER = {'INTERPRETED': 0, 'DECISION': 1, 'CITED': 2}
INPUT_STATES = {'MISSING': '値がない', 'EXTERNAL_REFERENCE': '外部参照の実値が未確定', 'PARTIAL': '一部の値が未確定',
                'EXPRESSION_UNRESOLVED': '式の値が未確定', 'SECRET_REFERENCE': '秘密の参照（実値は確認しない）',
                'NOT_INSPECTED': '検査できない条件', 'UNDECIDED': '未決定', 'PARENT_UNRESOLVED': '親の値が未確定',
                'DEFAULT_REQUESTED': '既定値の採用が未許可', 'EMPTY': '空の値', 'NULL': 'null', 'OMITTED': '明示的に省略',
                'COMPOSITE': '入れ子の値を確認'}
SAMPLE = 10


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')

HEADERS = ['優先度', '状態', 'リソース', '項目', '値', '由来', '出典文書', '構成要素', '原文の位置', '原文', '理由', '判定(OK/NG)', 'コメント', 'item_id', 'fingerprint']


class Verdict(Strict):
    item_id: str = Field(min_length=1)
    fingerprint: str = Field(min_length=1)
    verdict: Literal['OK', 'NG']
    comment: str = ''
    reviewer: str = Field(min_length=1)
    recorded_at: str
    # Set only when agents' agreeing verdicts were recorded under a delegation policy.
    delegation: Basis | None = None


class Decisions(Strict):
    version: Literal['1']
    decisions: list[Verdict] = Field(default_factory=list)


def fingerprint(item_id, setting):
    data = setting.model_dump(mode='json', exclude={'rationale'}) if setting is not None else None
    return hashlib.sha256(json.dumps([item_id, data], ensure_ascii=False, sort_keys=True).encode('utf-8')).hexdigest()[:16]


def shown(setting):
    if setting is None:return ''
    if setting.status != 'DECIDED':return setting.status
    if setting.classification == 'SECRET' or setting.mode == 'SECRET_REF':return '（秘密の参照）' if setting.mode == 'SECRET_REF' else '（秘密）'
    if setting.mode == 'RESOURCE_REF':return '→ ' + (', '.join(setting.ref) if isinstance(setting.ref, list) else str(setting.ref))
    if setting.mode in ('DEFAULT', 'OMITTED'):return setting.mode
    if setting.mode == 'EXTERNAL_REF':return '外部参照 ' + (', '.join(setting.ref) if isinstance(setting.ref, list) else str(setting.ref or ''))
    value = setting.expression if setting.mode == 'EXPRESSION' else setting.value
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 80 else text[:77] + '…'


def tier_of(item, trace, grounded=None):
    """How the value was made, from recorded facts only; anything unrecorded is an interpretation."""
    setting = item.expected
    if setting.status != 'DECIDED':return None
    if setting.mode == 'DEFAULT':return 'ASSUMED'
    if item.origin == 'decision':return 'DECISION'
    snapshot = trace.get(item.item_id)
    if snapshot and snapshot.get('verification_status') == 'DICTIONARY_APPROVED':
        return 'TRANSCRIBED' if snapshot.get('conversion') == 'AS_WRITTEN' else 'CONVERTED'
    # Found in the cells it cites: the value is the document's, though which property it went to is still read by a person.
    if (grounded or {}).get(item.input_pointer) == 'GROUNDED':return 'CITED'
    return 'INTERPRETED'


def short(text, limit=80):
    text = ' '.join(str(text or '').split())
    return text if len(text) <= limit else text[:limit - 1] + '…'


def evidence(item, snapshot, design, resources):
    """Where the value was read and what the original says: the trace's cell and text, else the first source and the rationale."""
    if snapshot:
        label = snapshot.get('label');value = snapshot.get('value')
        return snapshot.get('_pointer', ''), short(f'{label}：{value}' if label else value)
    resource = resources.get(item.resource_id)
    decision = next((d for d in getattr(design, 'decisions', None) or [] if d.id in (getattr(item.expected, 'decision_ids', None) or [])), None)
    if not item.expected.sources and decision is not None:
        locator = next((s.locator for s in design.sources if decision.sources and s.id == decision.sources[0]), '')
        return locator, short(f'方針 {decision.title}：{decision.statement}')
    cited = list(item.expected.sources) or (list(resource.sources) if resource else [])
    locator = next((s.locator for s in design.sources if cited and s.id == cited[0]), '')
    return locator, short(item.expected.rationale)


def why(matrix_row, label):
    states = [INPUT_STATES.get(s, s) for s in matrix_row.get('input_states', []) if s != 'MISSING' or label == '要確認']
    if matrix_row.get('setting_status') == 'UNDECIDED' and '未決定' not in states:states.insert(0, '未決定')
    return (label + (f"（{'・'.join(states)}）" if states else '')
            + ('：' + open_path_text(matrix_row) if matrix_row.get('open_paths') else ''))


def findings_by_path(rows, key):
    found = {}
    for row in rows:
        found.setdefault(row.get('resource_id'), []).append((row.get('path') or '', row.get(key), row.get('rule_id') or row.get('policy_id'), row.get('reason')))
    return found


def build(document, matrix, trace_rows=None, source_check=None, decisions=None, overview=None, overview_report=None, grounding=None):
    """`grounding` is the grounding check's report of the same input, when the approved documents were read."""
    grounded = {r['pointer']: r['status'] for r in (grounding or {}).get('rows', [])}
    trace = {}
    for row in trace_rows or []:
        for item_id in row.get('item_ids', []):trace[item_id] = {**(row.get('source_snapshot') or {}), '_pointer': row.get('source_pointer', '')}
    matrix_rows = {r['item_id']: r for r in matrix['rows']}
    evaluation = findings_by_path([r for r in document.evaluation.results if r.get('verdict') in ('FAIL', 'ERROR')], 'verdict')
    policy = findings_by_path([r for r in document.project_policy.rows if r.get('result') in ('FAIL', 'NEEDS_REVIEW')], 'result')
    stale = [w for w in (source_check or {}).get('warnings', []) if w.get('code') == 'STALE_VALUE_IN_DESIGN']
    accepted = {d['item_id']: d for d in (decisions or {}).get('decisions', []) if d.get('verdict') == 'OK'}
    rejected = {d['item_id']: d for d in (decisions or {}).get('decisions', []) if d.get('verdict') == 'NG'}
    resources = {r.id: r for r in document.design.resources}
    rows, seen = [], set()

    def hits(found, resource_id, path):
        return [f for f in found.get(resource_id, []) if f[0] == path or f[0].startswith(path + '/')]

    for item in document.items:
        if item.origin == 'cfn_only':continue
        seen.add(item.item_id)
        m = matrix_rows.get(item.item_id, {})
        path = '/properties/' + item.name
        tier = tier_of(item, trace, grounded)
        reasons = []
        state = m.get('state', 'CONFIRMED')
        if state in ('MISSING', 'REVIEW'):reasons.append(why(m, '未記載' if state == 'MISSING' else '要確認'))
        if tier == 'ASSUMED':reasons.append('既定値に依存' if item.expected.mode == 'DEFAULT' else '推定')
        if 'NO_SOURCE' in m.get('flags', []):reasons.append('出典なし')
        for _, verdict, rule, _ in hits(evaluation, item.resource_id, path):reasons.append(f'AWS検査 {verdict} {rule}')
        for _, result, rule, _ in hits(policy, item.resource_id, path):reasons.append(f'方針 {result} {rule}')
        for w in stale:
            if w['pointer'].startswith(item.input_pointer + '/') or w['pointer'] == item.input_pointer:reasons.append(f"旧版にだけある値 {w['value']}")
        if item.comparison == 'DIFFERENT':reasons.append('CFNと相違')
        fp = fingerprint(item.item_id, item.expected)
        notes = [{'REFERENCE_ONLY': '出典が参考文書だけ', 'RESOURCE_SOURCE_ONLY': '出典がリソース単位だけ',
                  'NOT_IN_SOURCE_SET': '出典が文書セット外'}[f] for f in m.get('flags', []) if f != 'NO_SOURCE']
        group = CAUSE_GROUPS.get(getattr(item.expected, 'cause', None)) if item.expected.status != 'DECIDED' else None
        if reasons and group:
            ask = getattr(item.expected, 'ask', None)
            reasons.insert(0, group[1] + (f'（{ask}）' if ask else ''))
        if reasons:priority = 'P1'
        elif state == 'NOT_APPLICABLE':priority = 'P4'
        else:priority = 'P2' if notes and TIER_PRIORITY.get(tier, 'P2') in ('P3', 'P4') else TIER_PRIORITY.get(tier, 'P2')
        at, said = evidence(item, trace.get(item.item_id), document.design, resources)
        rows.append({'priority': priority, 'state': m.get('state_ja', ''), 'resource_id': item.resource_id,
                     'resource_type': resources[item.resource_id].type if item.resource_id in resources else None,
                     'property': item.name, 'value': shown(item.expected), 'tier': tier, 'tier_ja': TIERS.get(tier, ''),
                     'documents': m.get('documents', []), 'reasons': reasons + notes, 'item_id': item.item_id,
                     'input_pointer': item.input_pointer, 'fingerprint': fp, 'evidence_at': at, 'evidence': said,
                     'group': group[0] if group else 1})
    for m in matrix['rows']:
        if m['item_id'] in seen or m['state'] not in ('MISSING', 'REVIEW'):continue
        rows.append({'priority': 'P1', 'state': m['state_ja'], 'resource_id': m['resource_id'], 'resource_type': m['resource_type'],
                     'property': m['property'], 'value': '', 'tier': None, 'tier_ja': '', 'documents': m['documents'],
                     'reasons': [why(m, '必要入力が未記載' if m['state'] == 'MISSING' else '必要入力の条件・値を確認')], 'item_id': m['item_id'],
                     'input_pointer': m.get('input_pointer'), 'fingerprint': fingerprint(m['item_id'], None), 'evidence_at': '', 'evidence': ''})
    item_paths = {(r['resource_id'], '/properties/' + r['property']) for r in rows}
    for found, label in ((evaluation, 'AWS検査'), (policy, '方針')):
        for resource_id, entries in sorted(found.items(), key=lambda x: str(x[0])):
            for path, verdict, rule, reason in entries:
                if any(path == p or path.startswith(p + '/') for r, p in item_paths if r == resource_id):continue
                rows.append({'priority': 'P1', 'state': '', 'resource_id': resource_id, 'resource_type': None,
                             'property': path or '（リソース全体）', 'value': '', 'tier': None, 'tier_ja': '', 'documents': [],
                             'reasons': [f'{label} {verdict} {rule}' + (f'：{reason}' if reason else '')],
                             'item_id': f'{resource_id}.{path or "@resource"}', 'input_pointer': None, 'fingerprint': '', 'evidence_at': '', 'evidence': ''})
    if overview_report is not None:
        # Overview gaps and conflicts are decisions for people; a resource outside the overview is shown on that resource.
        for f in overview_report['findings']:
            if f['category'] == 'OPEN':continue
            on_resource = f['code'] == 'RESOURCE_NOT_IN_OVERVIEW'
            rows.append({'priority': 'P1', 'state': '', 'resource_id': f['target'] if on_resource else '（システム概要）', 'resource_type': None,
                         'property': '（リソース全体）' if on_resource else f['target'], 'value': '', 'tier': None, 'tier_ja': '', 'documents': [],
                         'reasons': [f"概要 {f['category']} {f['meaning']}" + (f"：{f['detail']}" if f['detail'] else '')],
                         'item_id': f"overview.{f['code'].lower()}.{f['target']}", 'input_pointer': None, 'fingerprint': '', 'evidence_at': '', 'evidence': ''})
    placed = {}
    if overview is not None:
        for c in overview.components:
            for resource_id in c.realized_by.resources:placed.setdefault(resource_id, []).append(c)
    for row in rows:
        components = placed.get(row['resource_id'], [])
        row['components'] = [f'{c.name}（{c.id}）' for c in components]
        row['requirements'] = sorted({r for c in components for r in c.requirement_ids})
    for row in rows:
        fp, item_id = row['fingerprint'], row['item_id']
        if not fp:continue
        if item_id in rejected:
            row['reasons'].append('前回NG' + ('（未修正）' if rejected[item_id]['fingerprint'] == fp else '（修正あり）'));row['priority'] = 'P1'
        elif item_id in accepted and accepted[item_id]['fingerprint'] != fp:row['reasons'].append('前回OK後に変更');row['priority'] = 'P1'
        elif item_id in accepted and row['priority'] != 'P1':row['priority'] = 'DONE'
    order = list(PRIORITIES)
    def within(r):return r.get('group', 1) if r['priority'] == 'P1' else TIER_ORDER.get(r['tier'], 0) if r['priority'] == 'P2' else 0
    rows.sort(key=lambda r: (order.index(r['priority']), within(r), str(r['resource_id']), r['property']))
    for r in rows:r.pop('group', None)
    counts = Counter(r['priority'] for r in rows)
    return {'version': '1', 'environment': document.environment_id,
            'summary': {'rows': len(rows), 'priorities': {p: counts.get(p, 0) for p in PRIORITIES},
                        'tiers': dict(sorted(Counter(r['tier'] for r in rows if r['tier']).items())),
                        'decisions_applied': decisions is not None,
                        'input_completeness': document.checklist.status, 'aws_assessment': document.evaluation.assessment,
                        'project_policy_assessment': document.project_policy.assessment,
                        'system_overview_assessment': overview_report['assessment'] if overview_report else 'NOT_PROVIDED'},
            'rows': rows,
            'notice': '優先度はレビューの順序であり、承認ではない。確定・GENERATED・COMPLETEは入力と処理の状態を表す。'}


def table(rows):
    lines = ['| 状態 | リソース | 項目 | 値 | 由来 | 構成要素 | 原文 | 理由 |', '|---|---|---|---|---|---|---|---|']
    for r in rows:
        source = ' '.join(x for x in (r['evidence_at'] or '、'.join(r['documents']), short(r['evidence'], 60)) if x)
        cells = [r['state'] or '—', str(r['resource_id']), r['property'], (r['value'] or '—').replace('|', '\\|'), r['tier_ja'] or '—',
                 '、'.join(r.get('components', [])) or '—', (source or '—').replace('|', '\\|'), '、'.join(r['reasons']) or '—']
        lines.append('| ' + ' | '.join(cells) + ' |')
    return lines


def render(pack):
    s = pack['summary'];p = s['priorities']
    by = {k: [r for r in pack['rows'] if r['priority'] == k] for k in PRIORITIES}
    lines = ['# レビューパック', '',
             f"{s['rows']}行のうち、判断が必要 {p['P1']}・解釈の確認 {p['P2']}・抜取り確認 {p['P3']}・確認不要 {p['P4']}"
             + (f"・前回確認済み {p['DONE']}" if s['decisions_applied'] else '') + '。'
             f"必要入力 {s['input_completeness']}、AWS検査 {s['aws_assessment']}、案件方針 {s['project_policy_assessment']}。", '',
             '由来：' + '、'.join(f'{v}（{k}）' for k, v in TIERS.items()) + '。記録のない値は「解釈」として扱う。'
             '「セルに記載」は引用したセルに同じ値があることを機械で確かめた値で、どの項目に当てたかは人が確かめる。', '',
             '判断が必要な行は、人の判断、その他の不足・指摘、設計者の宿題、構築時の注意の順に並べる。'
             '解釈の確認は、セルにない値（換算・解釈）を先に、セルに記載の値を後に並べる。', '',
             f"## 1. 判断が必要（{p['P1']}件）", '']
    lines += table(by['P1']) if by['P1'] else ['なし。']
    lines += ['', f"## 2. 解釈の確認（{p['P2']}件）", '', '原文との対応を人が確かめる値。', '']
    lines += table(by['P2']) if by['P2'] else ['なし。']
    sample = by['P3'][::max(1, len(by['P3']) // SAMPLE)][:SAMPLE]
    lines += ['', f"## 3. 抜取り確認（{p['P3']}件中{len(sample)}件）", '', '承認済み辞書で変換した値。変換規則が正しければ残りも正しい。', '']
    lines += table(sample) if sample else ['なし。']
    lines += ['', f"## 4. 確認不要（{p['P4']}件）", '', '承認済み辞書でセルの値をそのまま転記した値と対象外の項目。一覧は review-pack.xlsx にある。']
    if s['decisions_applied']:lines += ['', f"前回OKとした{p['DONE']}件は、値が変わっていないため省いた。"]
    lines += ['', '---', '', pack['notice']]
    return '\n'.join(lines) + '\n'


def workbook(pack):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation
    book = Workbook();sheet = book.active;sheet.title = 'レビュー'
    sheet.append(HEADERS)
    fills = {k: PatternFill('solid', fgColor=v) for k, v in {'P1': 'F8D7DA', 'P2': 'FFF3CD', 'P3': 'E2EFDA', 'P4': 'EDEDED', 'DONE': 'EDEDED'}.items()}
    # Rows are counted here: openpyxl's max_row scans every cell, which made large packs quadratic.
    number = 1
    for r in pack['rows']:
        values = [PRIORITIES[r['priority']], r['state'], str(r['resource_id']), r['property'], r['value'], r['tier_ja'],
                  '、'.join(r['documents']), '、'.join(r.get('components', [])), r['evidence_at'], r['evidence'], '、'.join(r['reasons']), '', '', r['item_id'], r['fingerprint']]
        sheet.append(values);number += 1
        for column, value in enumerate(values, 1):
            if isinstance(value, str):sheet.cell(number, column).data_type = 's'
        sheet.cell(number, 1).fill = fills[r['priority']]
    for cell in sheet[1]:cell.font = Font(bold=True)
    check = DataValidation(type='list', formula1='"OK,NG"', allow_blank=True)
    sheet.add_data_validation(check);check.add(f'L2:L{max(2, number)}')
    for column, width in zip('ABCDEFGHIJKLMNO', (18, 8, 22, 28, 30, 12, 26, 24, 26, 36, 40, 12, 30, 30, 18)):sheet.column_dimensions[column].width = width
    sheet.freeze_panes = 'A2';sheet.auto_filter.ref = sheet.dimensions
    summary = book.create_sheet('概要')
    for key, label in PRIORITIES.items():summary.append([label, pack['summary']['priorities'][key]])
    summary.append([]);summary.append([pack['notice']])
    return book


def record(workbook_path, reviewer, *, now=None):
    """Reviewer verdicts from the pack workbook, bound to each row's fingerprint."""
    from openpyxl import load_workbook
    try:reviewer = person_name(reviewer, 'REVIEWER')
    except DelegationError as exc:raise ValueError(str(exc)) from None
    sheet = load_workbook(workbook_path, read_only=True)['レビュー']
    rows = sheet.iter_rows(values_only=True)
    header = list(next(rows))
    if header[:len(HEADERS)] != HEADERS:raise ValueError('NOT_A_REVIEW_PACK: unexpected header row')
    at = {h: i for i, h in enumerate(header)}
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    decisions = []
    for row in rows:
        verdict = str(row[at['判定(OK/NG)']] or '').strip().upper()
        if not verdict:continue
        if verdict not in ('OK', 'NG'):raise ValueError(f"INVALID_VERDICT: {row[at['item_id']]}")
        if not row[at['fingerprint']]:continue
        decisions.append({'item_id': row[at['item_id']], 'fingerprint': row[at['fingerprint']], 'verdict': verdict,
                          'comment': str(row[at['コメント']] or ''), 'reviewer': reviewer.strip(), 'recorded_at': stamp})
    return Decisions.model_validate({'version': '1', 'decisions': decisions}).model_dump(exclude_none=True)


def merge(previous, new):
    """Later verdicts replace earlier ones for the same item."""
    kept = {d['item_id']: d for d in (previous or {}).get('decisions', [])}
    for d in new['decisions']:kept[d['item_id']] = d
    return {'version': '1', 'decisions': [kept[k] for k in sorted(kept)]}


def checked(decisions):
    """A decisions file as written: validated against its contract."""
    return Decisions.model_validate(decisions).model_dump(exclude_none=True)


FINDING_COLUMNS = ('id', 'resource_id', 'resource_type', 'property', 'note')


def load_findings(path):
    """Past human review findings: JSON list, CSV or the first sheet of a workbook with the columns above."""
    path = Path(path)
    if path.suffix.lower() == '.json':
        raw = json.loads(path.read_text(encoding='utf-8'));records = raw.get('findings', raw) if isinstance(raw, dict) else raw
    elif path.suffix.lower() == '.csv':
        import csv
        with path.open(encoding='utf-8-sig', newline='') as handle:records = list(csv.DictReader(handle))
    elif path.suffix.lower() in ('.xlsx', '.xlsm'):
        from openpyxl import load_workbook
        sheet = load_workbook(path, read_only=True, data_only=True).worksheets[0]
        values = list(sheet.iter_rows(values_only=True))
        header = [str(h or '').strip() for h in values[0]] if values else []
        records = [dict(zip(header, row)) for row in values[1:] if any(v not in (None, '') for v in row)]
    else:raise ValueError('UNSUPPORTED_FINDINGS_FORMAT: use .json, .csv or .xlsx')
    findings = []
    for record in records:
        finding = {k: str(record.get(k) or '').strip() for k in FINDING_COLUMNS}
        if not finding['id']:raise ValueError('FINDING_ID_REQUIRED')
        if not finding['resource_id'] and not finding['resource_type']:raise ValueError(f"FINDING_TARGET_REQUIRED: {finding['id']}")
        finding['property'] = finding['property'].removeprefix('/properties').strip('/')
        findings.append(finding)
    if len({f['id'] for f in findings}) != len(findings):raise ValueError('DUPLICATE_FINDING_ID')
    return findings


def matches(finding, row):
    if finding['resource_id'] and finding['resource_id'] != str(row['resource_id']):return False
    if finding['resource_type'] and row.get('resource_type') and finding['resource_type'] != row['resource_type']:return False
    wanted, have = finding['property'], str(row['property']).removeprefix('/properties').strip('/')
    return not wanted or wanted == have or wanted.startswith(have + '/') or have.startswith(wanted + '/')


def recall(findings, pack):
    """Would the pack have sent the reviewer to what people actually found? Recall at P1 and P1+P2, with the workload it cost."""
    order = list(PRIORITIES)
    results = []
    for finding in findings:
        hit = sorted((r for r in pack['rows'] if matches(finding, r)), key=lambda r: order.index(r['priority']))
        best = hit[0] if hit else None
        results.append({'id': finding['id'], 'priority': best['priority'] if best else None, 'item_id': best['item_id'] if best else None,
                        'reasons': best['reasons'] if best else []})
    count = lambda wanted: sum(r['priority'] in wanted for r in results)
    workload = {p: sum(r['priority'] == p for r in pack['rows']) for p in ('P1', 'P2')}
    p1_rows = [r for r in pack['rows'] if r['priority'] == 'P1']
    total = len(findings)
    return {'version': '1', 'findings': total,
            'recall_p1': round(count({'P1'}) / total, 4) if total else None,
            'recall_p1_p2': round(count({'P1', 'P2'}) / total, 4) if total else None,
            'workload': workload, 'p1_rows_matching_a_finding': sum(any(matches(f, r) for f in findings) for r in p1_rows),
            'not_in_pack': [r['id'] for r in results if r['priority'] is None],
            'below_p2': [r['id'] for r in results if r['priority'] in ('P3', 'P4', 'DONE')], 'results': results,
            'limitations': ['対応付けはリソースと項目の一致だけで、指摘の内容と理由の一致は見ない。', '過去の指摘は網羅的な正解ではない。']}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design review-pack', description='Record reviewer verdicts from review-pack.xlsx and measure the recall of past review findings')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('record', help='read OK/NG verdicts from a review-pack workbook')
    p.add_argument('--workbook', required=True);p.add_argument('--reviewer', required=True, help='the person who reviewed, as the user names them')
    p.add_argument('--previous', help='earlier decisions file to carry forward');p.add_argument('--output', required=True)
    p = sub.add_parser('import', help='verdicts exported from review-pack.html, checked against the pack')
    p.add_argument('--file', required=True);p.add_argument('--pack', required=True);p.add_argument('--previous');p.add_argument('--output', required=True)
    p = sub.add_parser('recall', help='how many past human review findings the pack surfaced at P1 and P1+P2')
    p.add_argument('--findings', required=True, help='JSON, CSV or XLSX with id, resource_id or resource_type, property, note')
    p.add_argument('--pack', required=True, help='review-pack.json of the same design')
    args = parser.parse_args(argv)
    try:
        if args.command == 'import':
            from .review_page import imported
            output = Path(args.output)
            if output.exists():raise ValueError('output already exists; use a fresh path')
            decisions, problems = imported(json.loads(Path(args.file).read_text(encoding='utf-8')), json.loads(Path(args.pack).read_text(encoding='utf-8')))
            if problems:raise ValueError('REFUSED: ' + '；'.join(problems))
            if args.previous:decisions = merge(json.loads(Path(args.previous).read_text(encoding='utf-8')), decisions)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(checked(decisions), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            counts = Counter(d['verdict'] for d in decisions['decisions'])
            print(json.dumps({'decisions': args.output, 'OK': counts.get('OK', 0), 'NG': counts.get('NG', 0)}));return 0
        if args.command == 'recall':
            report = recall(load_findings(args.findings), json.loads(Path(args.pack).read_text(encoding='utf-8')))
            print(json.dumps(report, ensure_ascii=False, indent=2));return 0
        output = Path(args.output)
        if output.exists():raise ValueError('output already exists; use a fresh path')
        output.parent.mkdir(parents=True, exist_ok=True)
        decisions = record(args.workbook, args.reviewer)
        if args.previous:decisions = merge(json.loads(Path(args.previous).read_text(encoding='utf-8')), decisions)
        output.write_text(json.dumps(checked(decisions), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        counts = Counter(d['verdict'] for d in decisions['decisions'])
        print(json.dumps({'decisions': args.output, 'OK': counts.get('OK', 0), 'NG': counts.get('NG', 0)}));return 0
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc) if isinstance(exc, ValueError) else type(exc).__name__}, ensure_ascii=False));return 2


if __name__ == '__main__':
    raise SystemExit(main())
