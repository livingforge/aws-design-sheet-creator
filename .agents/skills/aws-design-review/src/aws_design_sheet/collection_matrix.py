"""Collection matrix: what the design needs, what was collected, and which documents it came from.

One row per design setting or required-input obligation, with four states for people
(確定・要確認・未記載・対象外) and the documents its sources name. Flags point at confirmed
values without a source and at values backed only by reference documents. The matrix
shows where facts came from; it does not judge whether they were read correctly.
"""
from collections import Counter

STATES = {'CONFIRMED': '確定', 'REVIEW': '要確認', 'MISSING': '未記載', 'NOT_APPLICABLE': '対象外'}
FLAGS = {'NO_SOURCE': '確定値に出典がない', 'RESOURCE_SOURCE_ONLY': '出典がリソース単位だけ',
         'REFERENCE_ONLY': '出典が参考文書だけ', 'NOT_IN_SOURCE_SET': '出典が文書セットにない'}
ORDER = ['MISSING', 'REVIEW', 'CONFIRMED', 'NOT_APPLICABLE']


def view_state(setting_status, results):
    """Collapse setting status and checklist results into the four states people review."""
    results = set(results)
    if 'MISSING' in results:return 'MISSING'
    if results & {'NEEDS_REVIEW', 'BRANCH_CONFLICT'} or setting_status == 'UNDECIDED':return 'REVIEW'
    if setting_status == 'NOT_APPLICABLE' or (setting_status is None and results and results <= {'NOT_APPLICABLE'}):return 'NOT_APPLICABLE'
    return 'CONFIRMED' if setting_status == 'DECIDED' else 'MISSING'


def deepest(entries):
    """Open nested paths without those that only contain another open one, in path order."""
    unique = {(e['path'], e['result'], e['input_state']): e for e in entries}
    paths = {e['path'] for e in unique.values()}
    return [e for _, e in sorted(unique.items(), key=lambda kv: (kv[0][0], kv[0][1], str(kv[0][2])))
            if not any(p.startswith(e['path'] + '/') for p in paths)]


def open_path_text(row, limit=5):
    """The open nested paths of a row for people, e.g. `0/IpProtocol`; values to review are marked in a missing row."""
    entries = sorted(row.get('open_paths') or [], key=lambda e: (e['result'] != 'MISSING', e['path']))
    shown = [('要確認 ' if row.get('state') == 'MISSING' and e['result'] != 'MISSING' else '') + e['path'] for e in entries]
    return '、'.join(shown[:limit]) + (f' ほか{len(shown) - limit}件' if len(shown) > limit else '')


def build(document, source_check=None):
    design = document.design
    resources = {r.id: r for r in design.resources}
    decisions = {d.id: d for d in getattr(design, 'decisions', None) or []}
    references = {(c.source, c.property) for c in design.connections if c.kind == 'REFERENCE' and c.property}
    citations = {c['source']: c for c in (source_check or {}).get('citations', [])}

    def document_of(source_id):
        if source_check is not None:
            row = citations.get(source_id) or {}
            return row.get('document'), row.get('status')
        source = next((s for s in design.sources if s.id == source_id), None)
        return (source.locator.split('#', 1)[0] if source else None), None

    rows = {}
    for item in document.items:
        resource = resources.get(item.resource_id)
        rows[item.item_id] = {'item_id': item.item_id, 'resource_id': item.resource_id, 'resource_type': resource.type if resource else None,
                              'property': item.name, 'input_pointer': item.input_pointer, 'necessity': None,
                              'setting_status': item.expected.status, 'checklist_results': [],
                              'sources': list(item.expected.sources),
                              'decision_ids': [d for d in getattr(item.expected, 'decision_ids', None) or [] if d in decisions],
                              'declared_reference': item.expected.mode == 'RESOURCE_REF' and (item.resource_id, item.name) in references}
    for check_row in document.checklist.rows:
        key = check_row.get('item_id') or f"{check_row['resource_id']}.{check_row['path']}"
        row = rows.setdefault(key, {'item_id': key, 'resource_id': check_row['resource_id'], 'resource_type': check_row.get('resource_type'),
                                    'property': check_row['path'].removeprefix('/properties').lstrip('/') or '（選択肢の組合せ）', 'input_pointer': check_row.get('input_pointer'),
                                    'necessity': None, 'setting_status': None, 'checklist_results': [], 'sources': []})
        row['checklist_results'].append(check_row['result'])
        if check_row['result'] in ('MISSING', 'NEEDS_REVIEW', 'BRANCH_CONFLICT') and check_row.get('input_state'):
            row.setdefault('input_states', []).append(check_row['input_state'])
        # A row is per top-level property; keep which nested value inside it is still open.
        top = '/properties/' + row['property'].replace('~', '~0').replace('/', '~1')
        if check_row['result'] in ('MISSING', 'NEEDS_REVIEW', 'BRANCH_CONFLICT') and check_row['path'].startswith(top + '/'):
            row.setdefault('open_paths', []).append({'path': check_row['path'][len(top) + 1:], 'result': check_row['result'],
                                                     'input_state': check_row.get('input_state')})
        if check_row.get('necessity') and row['necessity'] != 'REQUIRED':row['necessity'] = check_row['necessity']
        for source in check_row.get('input_sources') or []:
            if source.get('id') and source['id'] not in row['sources']:row['sources'].append(source['id'])
    supported = Counter()
    for row in rows.values():
        row['checklist_results'] = sorted(set(row['checklist_results']))
        row['input_states'] = sorted(set(row.get('input_states', [])))
        row['open_paths'] = deepest(row.get('open_paths', []))
        row['state'] = view_state(row['setting_status'], row['checklist_results'])
        row['state_ja'] = STATES[row['state']]
        resource = resources.get(row['resource_id'])
        # A value realizing a declared decision, or a reference declared as a connection, has a basis even without its own sources.
        linked = row.get('decision_ids', [])
        row['source_level'] = ('SETTING' if row['sources'] else 'DECISION' if linked else 'CONNECTION' if row.get('declared_reference')
                               else 'RESOURCE' if resource and resource.sources else 'NONE')
        cited = (row['sources'] or sorted({s for d in linked for s in decisions[d].sources})
                 or (list(resource.sources) if resource and row['source_level'] != 'CONNECTION' else []))
        found = [document_of(s) for s in cited]
        row['documents'] = sorted({d for d, _ in found if d})
        flags = []
        if row['state'] == 'CONFIRMED':
            if row['source_level'] == 'NONE':flags.append('NO_SOURCE')
            elif row['source_level'] == 'RESOURCE':flags.append('RESOURCE_SOURCE_ONLY')
        if source_check is not None and cited:
            statuses = {s for _, s in found}
            if statuses == {None}:flags.append('NOT_IN_SOURCE_SET')
            elif statuses <= {'REFERENCE', None} and 'REFERENCE' in statuses:flags.append('REFERENCE_ONLY')
        row['flags'] = flags
        for d in row['documents']:supported[d] += 1
    ordered = sorted(rows.values(), key=lambda r: (ORDER.index(r['state']), r['resource_id'], r['property']))
    documents = []
    for source in design.sources:
        d, status = document_of(source.id)
        documents.append({'source_id': source.id, 'title': source.title, 'document': d, 'status': status, 'rows_supported': supported.get(d, 0) if d else 0})
    flags = Counter(f for r in ordered for f in r['flags'])
    return {'version': '1', 'summary': {'rows': len(ordered), 'states': {s: sum(r['state'] == s for r in ordered) for s in ORDER},
                                        'flags': dict(sorted(flags.items())), 'source_set': source_check is not None},
            'documents': documents, 'current_not_cited': (source_check or {}).get('current_not_cited'),
            'rows': ordered,
            'limitations': ['出典の有無と引用先だけを示す。値が原文どおりに読み取られたかは示さない。',
                            '行は設計の設定と必要入力の義務であり、AWSの全プロパティではない。']}


def render(matrix):
    s = matrix['summary']
    lines = ['# 収集マトリクス', '', f"{s['rows']}行。" + '・'.join(f"{STATES[k]} {v}" for k, v in s['states'].items()) + '。'
             + ('' if s['source_set'] else '文書セットの照合なし。'), '']
    if s['flags']:
        lines += ['| 注意 | 件数 |', '|---|---:|'] + [f'| {FLAGS[k]}（{k}） | {v} |' for k, v in s['flags'].items()] + ['']
    lines += ['## 文書ごとの寄与', '', '| 出典ID | 文書 | 状態 | 裏付ける行 |', '|---|---|---|---:|']
    lines += [f"| {d['source_id']} | {d['document'] or '—'} | {d['status'] or '—'} | {d['rows_supported']} |" for d in matrix['documents']]
    if matrix.get('current_not_cited'):
        lines += ['', '現行文書のうち一度も引用されていないもの（読み落としの可能性）：' + '、'.join(matrix['current_not_cited'])]
    problems = [r for r in matrix['rows'] if r['state'] in ('MISSING', 'REVIEW') or r['flags']]
    lines += ['', f'## 確認が必要な行（{len(problems)}件）', '']
    if problems:
        lines += ['| 状態 | リソース | 項目 | 文書 | 注意 |', '|---|---|---|---|---|']
        lines += [f"| {r['state_ja']} | {r['resource_id']} | {r['property']}{'：' + open_path_text(r) if r.get('open_paths') else ''} | {'、'.join(r['documents']) or '—'} | "
                  f"{'、'.join(FLAGS[f] for f in r['flags']) or '—'} |" for r in problems]
    else:lines.append('なし。')
    lines += ['', '全行は collection-matrix.json にある。'] + [f'- {x}' for x in matrix['limitations']]
    return '\n'.join(lines) + '\n'
