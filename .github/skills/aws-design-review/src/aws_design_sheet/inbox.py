"""Decision inbox: every decision a workspace is waiting for, in one workbook, recorded in one step.

`make` gathers what people must decide now (source-set statuses, the overview agreement,
policy-pack adoption, the P1 and P2 rows of the latest review pack), each with the
recommendation and candidates that have a deterministic basis: the proposal's own status,
the only resource of the referenced type, requirements whose text names a missing quality
attribute, decisions that a boundary-crossing flow could cite. `decide` validates every
filled row first and then records them with the names written in the workbook or registered
for the role; a row without a person's name is refused. Candidates are never chosen here.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .delegation import is_agent

HEADERS = ['番号', '種類', '対象', '内容', '推奨', '候補', '判断', '判断者', '理由', 'key']
KINDS = {'SOURCE': '文書セット', 'OVERVIEW': '概要の合意', 'POLICY': '方針パックの採用', 'REVIEW': 'レビュー判定'}
ROLE = {'SOURCE': 'approver', 'OVERVIEW': 'architect', 'POLICY': 'adopter', 'REVIEW': 'reviewer'}
KEYWORDS = {'AVAILABILITY': ['可用性', '稼働率', 'sla', '停止'], 'RPO': ['rpo', '復旧時点', 'データ損失', 'バックアップ'],
            'RTO': ['rto', '復旧時間', '目標復旧', '復旧まで'], 'PERFORMANCE': ['性能', '応答', 'レスポンス', 'p95', 'スループット'],
            'RETENTION': ['保持', '保存期間', '保管期間'], 'CAPACITY': ['容量', '同時接続', 'ユーザー数'], 'SECURITY': ['暗号化', '認証', 'セキュリティ']}


class InputError(ValueError):
    pass


def candidates_for(row, design, overview, cat):
    """Deterministic candidates for one review-pack row, with a recommendation only when there is exactly one."""
    resources = design.get('resources', [])
    if row['resource_id'] == '（システム概要）' and overview is not None:
        reason = ' '.join(row['reasons'])
        if '必要な非機能の目標値がない' in reason:
            words = KEYWORDS.get(row['property'], [])
            found = [r['id'] for r in overview.get('requirements', []) if any(w in (r.get('title', '') + r.get('text', '')).lower() for w in words)]
            return [f'要件 {r} を確認' for r in found], (f'要件 {found[0]} の記載から目標値を決める' if len(found) == 1 else '')
        if '境界をまたぐ流れに方針' in reason:
            sections = {'security', 'network', 'edge'}
            found = [d['id'] for d in design.get('decisions', []) if d.get('section') in sections and d.get('status', 'DECIDED') == 'DECIDED']
            return [f'方針 {d}' for d in found], ''
        return [], ''
    if row.get('state') == '未記載' and cat is not None and row.get('resource_type'):
        targets, basis = cat.reference_targets(row['resource_type'], [row['property']]), '登録済みの参照情報'
        if not targets:
            # Without registered metadata, VpcId / KmsKeyArn style names point at the type of the same name.
            import re
            m = re.fullmatch(r'([A-Za-z]+?)(?:Id|Ids|Arn|Arns)', row['property'])
            targets = {r.get('type') for r in resources if m and r.get('type', '').split('::')[-1].lower() == m.group(1).lower()}
            basis = 'プロパティ名からの推定'
        found = [r['id'] for r in resources if targets and r.get('type') in targets]
        return [f'→ {r}' for r in found], (f'→ {found[0]}（設計内で唯一の {next(iter(targets))}、{basis}）' if len(found) == 1 else '')
    return [], ''


def make(workspace):
    from . import flow
    workspace = Path(workspace);config = flow.load(workspace)
    import yaml
    report = flow.status(workspace)
    stages = {s['stage']: s for s in report['stages']}
    rows = []

    def add(kind, target, content, recommendation='', candidates=(), decision='', key=None):
        rows.append({'kind': kind, 'target': target, 'content': content, 'recommendation': recommendation, 'candidates': list(candidates),
                     'decision': decision, 'key': key or {}})
    proposal, approved = workspace / 'sources' / 'proposal.json', workspace / 'sources' / 'set.json'
    if stages['sources']['state'] == 'WAITING_FOR_PERSON' and proposal.is_file() and not approved.is_file():
        for e in json.loads(proposal.read_text(encoding='utf-8'))['documents']:
            hint = {'ARCHIVE_FOLDER': 'SUPERSEDED', 'NEWEST_IN_ARCHIVE_FOLDER': 'CURRENT', 'POSSIBLY_REFERENCE': 'REFERENCE'}.get(e['reason'], '') \
                if e['status'] == 'UNDECIDED' else e['status']
            about = '、'.join(x for x in (e['signals'].get('title'), f"位置付け {e['signals']['role']}" if e['signals'].get('role') else None) if x)
            add('SOURCE', e['document_id'], f"系列 {e['family']}、版 {e['signals'].get('version') or '—'}、提案 {e['status']}（{e['reason']}）"
                + (f"、{about}" if about else ''), hint,
                ['CURRENT', 'SUPERSEDED', 'REFERENCE', 'EXCLUDED'], e['status'] if e['status'] != 'UNDECIDED' else '',
                {'proposed': e['status']})
    if stages['overview']['state'] in ('WAITING_FOR_PERSON', 'STALE') and config.get('overview'):
        add('OVERVIEW', config['overview'], stages['overview']['detail'], '', ['合意', '差し戻し'])
    if stages['policy']['state'] in ('WAITING_FOR_PERSON', 'STALE'):
        add('POLICY', config['policy_pack'], stages['policy']['detail'], '', ['採用', '不採用'])
    found = flow.runs(workspace)
    # Review rows wait for people only once gates pass and no agent review is pending for them.
    if found and stages['review']['state'] == 'WAITING_FOR_PERSON':
        latest = found[-1]
        pack = json.loads((latest / 'review-pack.json').read_text(encoding='utf-8'))
        design = json.loads((latest / 'design.json').read_text(encoding='utf-8'))['design']
        overview_path = flow.at(workspace, config.get('overview'))
        overview = yaml.safe_load(overview_path.read_bytes()) if overview_path and overview_path.is_file() else None
        try:
            from .document_catalog import catalog
            cat = catalog(design['environments'][0]['region'])
        except Exception:
            cat = None
        for r in pack['rows']:
            if r['priority'] not in ('P1', 'P2'):continue
            options, hint = candidates_for(r, design, overview, cat)
            add('REVIEW', f"{r['resource_id']}.{r['property']}", f"{r['priority']} {r.get('value') or '—'}：{'、'.join(r['reasons']) or r.get('tier_ja', '')}",
                hint, (['OK', 'NG'] if r['fingerprint'] else []) + options, '',
                {'run': latest.name, 'item_id': r['item_id'], 'fingerprint': r['fingerprint'], 'resource_id': r['resource_id'], 'property': r['property']})
    for i, r in enumerate(rows, 1):r['number'] = i
    return {'version': '1', 'workspace': str(workspace), 'rows': rows,
            'summary': {KINDS[k]: sum(r['kind'] == k for r in rows) for k in KINDS if any(r['kind'] == k for r in rows)}}


def workbook(inbox):
    from openpyxl import Workbook
    from openpyxl.styles import Font
    book = Workbook();sheet = book.active;sheet.title = '判断'
    sheet.append(HEADERS)
    for r in inbox['rows']:
        sheet.append([r['number'], KINDS[r['kind']], r['target'], r['content'], r['recommendation'], ' / '.join(r['candidates']), r['decision'], '', '',
                      json.dumps({'kind': r['kind'], **r['key']}, ensure_ascii=False)])
        for cell in sheet[sheet.max_row]:
            if isinstance(cell.value, str):cell.data_type = 's'
    for cell in sheet[1]:cell.font = Font(bold=True)
    for column, width in zip('ABCDEFGHIJ', (6, 14, 30, 60, 34, 34, 18, 14, 24, 10)):sheet.column_dimensions[column].width = width
    sheet.column_dimensions['J'].hidden = True
    sheet.freeze_panes = 'A2';sheet.auto_filter.ref = sheet.dimensions
    return book


def read(path):
    from openpyxl import load_workbook
    sheet = load_workbook(path, read_only=True, data_only=True)['判断']
    rows = sheet.iter_rows(values_only=True)
    header = [str(h or '') for h in next(rows)]
    if header[:len(HEADERS)] != HEADERS:raise InputError('NOT_AN_INBOX: unexpected header row')
    at = {h: i for i, h in enumerate(header)}
    return [{'target': row[at['対象']], 'decision': str(row[at['判断']] or '').strip(), 'person': str(row[at['判断者']] or '').strip(),
             'reason': str(row[at['理由']] or '').strip(), 'key': json.loads(row[at['key']])} for row in rows if row[at['key']]]


def decide(workspace, path, *, now=None):
    """Validate every filled row, then record them all; nothing is written when a row is refused."""
    from . import flow
    workspace = Path(workspace);config = flow.load(workspace)
    people = config.get('people') or {}
    rows = [r for r in read(path) if r['decision']]
    errors = []
    for r in rows:
        kind = r['key']['kind']
        r['person'] = r['person'] or people.get(ROLE[kind], '')
        if not r['person']:errors.append(f"{r['target']}: 判断者がない")
        elif is_agent(r['person']):errors.append(f"{r['target']}: 判断者にエージェント名は書けない（委任方針の範囲は aws-design flow run all が記録する）")
        allowed = {'SOURCE': {'CURRENT', 'SUPERSEDED', 'REFERENCE', 'EXCLUDED'}, 'OVERVIEW': {'合意', '差し戻し'}, 'POLICY': {'採用', '不採用'}}.get(kind)
        if allowed and r['decision'].upper() not in allowed and r['decision'] not in allowed:errors.append(f"{r['target']}: 判断「{r['decision']}」は選べない")
        if kind == 'REVIEW' and r['decision'].upper() not in ('OK', 'NG') and not r['decision'].startswith(('→ ', '方針 ')):
            errors.append(f"{r['target']}: OK、NG、または候補（「→ リソースID」「方針 ID」）を書く")
    import yaml
    design = yaml.safe_load(flow.at(workspace, config['input']).read_bytes()) if flow.at(workspace, config['input']).is_file() else {}
    resources = {x['id']: x for x in design.get('resources', [])}
    decisions = {d['id'] for d in design.get('decisions', [])}
    overview_path = flow.at(workspace, config.get('overview'))
    overview = yaml.safe_load(overview_path.read_bytes()) if overview_path and overview_path.is_file() else None
    for r in rows:
        if r['decision'].startswith('→ ') and r['decision'][2:].split('（')[0].strip() not in resources:
            errors.append(f"{r['target']}: {r['decision'][2:]} は設計入力にない")
        if r['decision'].startswith('方針 '):
            flows = {f['id'] for f in (overview or {}).get('flows', [])}
            if r['decision'][3:].strip() not in decisions or r['key'].get('property') not in flows:
                errors.append(f"{r['target']}: 方針 {r['decision'][3:].strip()} は概要の流れに結び付けられない")
    sources = [r for r in rows if r['key']['kind'] == 'SOURCE']
    if sources and len({r['person'] for r in sources}) > 1:errors.append('文書セットの判断者は1人にする')
    if errors:raise InputError('REFUSED: ' + '；'.join(errors))
    done = []
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    if sources:
        from .source_set import approve, dump
        settings = {r['target']: r['decision'].upper() for r in sources if r['decision'].upper() != r['key']['proposed']}
        approved = approve(Path(config['arp_root']), (workspace / 'sources' / 'proposal.json').read_bytes(), sources[0]['person'], settings, now=now)
        (workspace / 'sources' / 'set.json').write_bytes(dump(approved.model_dump()))
        done.append({'kind': 'SOURCE', 'person': sources[0]['person'], 'changed': sorted(settings)})
    stamp_name = stamp.replace(':', '').replace('-', '')
    links = [r for r in rows if r['key']['kind'] == 'REVIEW' and r['decision'].startswith('方針 ')]
    if links:
        for r in links:
            flow_item = next(f for f in overview['flows'] if f['id'] == r['key']['property'])
            flow_item['decision_ids'] = sorted({*flow_item.get('decision_ids', []), r['decision'][3:].strip()})
        target = overview_path.with_name(f'{overview_path.stem}-inbox-{stamp_name}.json')
        target.write_text(json.dumps(overview, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        config['overview'] = target.relative_to(workspace).as_posix()
        (workspace / flow.CONFIG).write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        done.append({'kind': 'LINK', 'overview': config['overview'], 'flows': len(links)})
    fixes = [r for r in rows if r['key']['kind'] == 'REVIEW' and r['decision'].startswith('→ ')]
    if fixes:
        source = flow.at(workspace, config['input'])
        for r in fixes:
            ref = r['decision'][2:].split('（')[0].strip()
            setting = resources[r['key']['resource_id']].setdefault('settings', {})
            setting[r['key']['property']] = {'mode': 'RESOURCE_REF', 'ref': ref, 'rationale': f"判断の受信箱で {r['person']} が選択（{stamp}）"}
        target = source.with_name(f"{source.stem}-inbox-{stamp_name}.json")
        target.write_text(json.dumps(design, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        config['input'] = target.relative_to(workspace).as_posix()
        (workspace / flow.CONFIG).write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        done.append({'kind': 'FIX', 'input': config['input'], 'references': len(fixes)})
    for r in rows:
        kind = r['key']['kind']
        if kind == 'OVERVIEW' and r['decision'] == '合意':
            from .system_overview import approve as agree
            raw = flow.at(workspace, config['overview']).read_bytes()
            record = agree(raw, r['person'], now=now)
            target = workspace / 'sources' / f"overview-approval-{record['overview_sha256'][:12]}.json"
            target.parent.mkdir(exist_ok=True);target.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            done.append({'kind': 'OVERVIEW', 'person': r['person']})
        elif kind == 'POLICY' and r['decision'] == '採用':
            import yaml
            from .policy_packs import apply as adopt, load as load_pack
            pack, digest = load_pack(config['policy_pack'], config.get('library'))
            result, _ = adopt(yaml.safe_load(flow.at(workspace, config['input']).read_bytes()), pack, digest, adopted_by=r['person'])
            flow.at(workspace, config['policy_input']).write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            done.append({'kind': 'POLICY', 'person': r['person']})
    verdicts = [r for r in rows if r['key']['kind'] == 'REVIEW' and r['decision'].upper() in ('OK', 'NG') and r['key'].get('fingerprint')]
    if verdicts:
        from .review_pack import checked, merge
        previous = flow.decisions(workspace)
        new = {'version': '1', 'decisions': [{'item_id': r['key']['item_id'], 'fingerprint': r['key']['fingerprint'], 'verdict': r['decision'].upper(),
                                               'comment': r['reason'], 'reviewer': r['person'], 'recorded_at': stamp} for r in verdicts]}
        merged = checked(merge(json.loads(previous[-1].read_text(encoding='utf-8')) if previous else None, new))
        target = workspace / 'reviews' / f"decisions-{verdicts[0]['key']['run']}-inbox-{hashlib.sha256(json.dumps(new).encode()).hexdigest()[:8]}.json"
        target.parent.mkdir(exist_ok=True);target.write_text(json.dumps(merged, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        done.append({'kind': 'REVIEW', 'verdicts': len(verdicts)})
    return done
