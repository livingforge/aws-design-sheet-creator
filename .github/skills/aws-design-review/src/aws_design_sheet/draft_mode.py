"""Draft mode: what `aws-design flow run all` settles itself so that an 80-point draft comes out before anyone is asked.

A workspace whose flow.json says `"mode": "draft"` gets a draft source set (UNDECIDED documents settled by rule), the
policy pack applied as an unadopted candidate, one reading per drawing document after the picture triage, an asks
ledger without the independent review, and gates that stop only on a broken contract or a failed generation. None
of it is anyone's approval: each record carries DRAFT_AGENT and a draft mark, and `aws-design flow mode --set final`
sets the draft records aside so that the final mode asks the people again. `report` writes draft-report.md, the one
page a person reads first. See docs/draft-mode.md.
"""
import json
from collections import Counter
from pathlib import Path

from .delegation import DRAFT_AGENT

REPORT = 'draft-report.md'


def is_draft_set(path):
    """Whether an approved source set file was made by a draft."""
    path = Path(path)
    if not path.is_file():return False
    try:return bool((json.loads(path.read_text(encoding='utf-8')).get('approval') or {}).get('draft'))
    except (ValueError, OSError):return False


def is_draft_policy_input(path, pack_id):
    """Whether a policy input holds the pack as an unadopted candidate, as a draft applies it."""
    try:design = json.loads(Path(path).read_text(encoding='utf-8'))
    except (ValueError, OSError):return False
    return any(isinstance(s, dict) and s.get('id') == f'pack-{pack_id}' and '（未採用の候補）' in str(s.get('title', ''))
               for s in design.get('sources', []) or [])


def do_sources(workspace, config):
    from .source_set import approve_draft, dump
    workspace = Path(workspace)
    raw = (workspace / 'sources' / 'proposal.json').read_bytes()
    made = approve_draft(Path(config['arp_root']), raw)
    (workspace / 'sources' / 'set.json').write_bytes(dump(made.model_dump()))
    counts = Counter(e.status for e in made.documents)
    return {'step': 'draft-sources', 'documents': dict(sorted(counts.items())),
            'settled': [{'document': e.document_id, 'reason': e.reason, 'status': e.status} for e in made.documents if e.decided == 'DRAFT']}


def do_policy(workspace, config):
    """The pack applied with no adopter: every declaration stays UNCONFIRMED, as a candidate for the final mode."""
    import yaml
    from . import flow
    from .policy_packs import apply, load
    source_input, policy_input = flow.at(workspace, config['input']), flow.at(workspace, config['policy_input'])
    pack, digest = load(config['policy_pack'], config.get('library'))
    result, report = apply(yaml.safe_load(source_input.read_bytes()), pack, digest)
    policy_input.parent.mkdir(parents=True, exist_ok=True)
    policy_input.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {'step': 'draft-policy', 'pack': pack.id, 'declarations': len(report['added'])}


def set_aside(path):
    """Move a draft record out of use beside itself as *.draft.json, never over an earlier one."""
    path = Path(path);target = path.with_name(path.stem + '.draft' + path.suffix);n = 1
    while target.exists():n += 1;target = path.with_name(f'{path.stem}.draft-{n}{path.suffix}')
    path.replace(target)
    return target


def switch(workspace, mode):
    """Set the workspace's mode. To final: the draft source set and the candidate policy input go aside, so that their
    stages wait for the approver and the adopter; readings, ledgers and the overview stay and gain the final checks."""
    from . import flow
    workspace = Path(workspace);config = flow.load(workspace)
    moved = []
    if mode == 'final':
        approved = workspace / 'sources' / 'set.json'
        if is_draft_set(approved):moved.append(str(set_aside(approved)))
        if config.get('policy_pack') and config.get('policy_input'):
            policy_input = flow.at(workspace, config['policy_input'])
            if policy_input.is_file() and is_draft_policy_input(policy_input, config['policy_pack']):moved.append(str(set_aside(policy_input)))
    previous = config.get('mode', 'final');config['mode'] = mode
    (workspace / flow.CONFIG).write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {'mode': mode, 'previous': previous, 'set_aside': moved}


# --- The draft report -----------------------------------------------------------------------------

def cell(text):return str(text).replace('|', '｜').replace('\n', ' ')


def sources_section(workspace):
    from .source_set import KINDS_JA, SourceSet
    path = Path(workspace) / 'sources' / 'set.json'
    if not path.is_file():return ['文書セットがまだない。']
    found = SourceSet.model_validate_json(path.read_bytes())
    counts = Counter(e.status for e in found.documents)
    current = [e for e in found.documents if e.status == 'CURRENT']
    lines = ['状態：' + '、'.join(f'{k} {v}' for k, v in sorted(counts.items())) +
             f"。CURRENT のうち PRIMARY {sum(e.relevance == 'PRIMARY' for e in current)}件、PERIPHERAL {sum(e.relevance == 'PERIPHERAL' for e in current)}件。"]
    settled = [e for e in found.documents if e.decided == 'DRAFT']
    if settled:
        lines += ['', '下書きの規則で決めた文書（違っていれば確定モードで承認者が --set で直す）：', '', '| 文書 | 未決の理由 | 下書きでの扱い |', '|---|---|---|']
        troubled = {i['document']: i['code'] for i in found.issues}
        lines += [f"| {cell(e.document_id)} | {cell(troubled.get(e.document_id) if e.status == 'EXCLUDED' and e.document_id in troubled else e.reason)} | {e.status} |"
                  for e in settled]
    families = Counter(e.family for e in current)
    unordered = sorted(e.document_id for e in current if families[e.family] > 1)
    if unordered:lines += ['', '版の新旧が分からず、どれも CURRENT にした系列の文書：' + '、'.join(unordered) + '。確定の前にどれが現行かを決める。']
    peripheral = [e for e in current if e.relevance == 'PERIPHERAL']
    if peripheral:
        lines += ['', 'PERIPHERAL（必要な値を探すときに読む。引用しなくても状態は変えない）：' +
                  '、'.join(f"{e.document_id}（{KINDS_JA.get(e.signals.kind, '種類不明')}）" for e in peripheral[:30]) + (f' ほか{len(peripheral) - 30}件' if len(peripheral) > 30 else '')]
    return lines


def diagrams_section(workspace, config):
    from .diagram_triage import KINDS_JA, load, triage_path
    path = triage_path(workspace)
    if not path.is_file():return ['画像の仕分けはない（CURRENT の文書に図形・画像がないか、確定モードで読んだ）。']
    triage = load(path.read_bytes())
    decisions = Counter(d.decision for d in triage.documents)
    lines = [f"図形・画像のある文書 {len(triage.documents)}件：構成を描く見込み {decisions.get('ARCHITECTURE', 0)}件、"
             f"描かない見込み {decisions.get('NOT_ARCHITECTURE', 0)}件、画像を見る前 {decisions.get('PENDING', 0)}件。"]
    looks = {k.sha256: k for k in triage.looks}
    kinds = Counter(k.kind for k in triage.looks)
    if kinds:lines.append('見た画像：' + '、'.join(f'{KINDS_JA[k]} {v}' for k, v in sorted(kinds.items())) + '。')
    skipped = Counter(p.skipped for d in triage.documents for p in d.pictures if p.skipped)
    if skipped:
        names = {'HAS_TEXT': '文字・代替テキストあり', 'READ_IN_ARP4': 'ARP4のグラフで読み取り済み', 'SMALL': '小さい（アイコン・ロゴ）',
                 'DUPLICATE': '同じ画像の2つ目以降', 'NO_FILE': '画像ファイルがない'}
        lines.append('見ていない画像：' + '、'.join(f'{names[k]} {v}' for k, v in sorted(skipped.items())) + '。')
    unviewable = [k for k in triage.looks if k.kind == 'UNVIEWABLE']
    if unviewable:lines.append(f'表示できず種類の分からない画像 {len(unviewable)}件（ARP4で範囲を描画すれば見られる）。')
    seen = sorted({s for k in looks.values() for s in k.services})
    if seen:lines.append('構成図の画像に描かれたAWSサービス：' + '、'.join(seen) + '。')
    return lines


def gates_section(latest):
    path = latest / 'gates.json' if latest else None
    if not path or not path.is_file():return ['ゲートを評価していない。']
    from .gates import GATES_JA, load
    report = load(path)
    lines = ['| ゲート | 結果 | 内容 |', '|---|---|---|']
    lines += [f'| {GATES_JA[g.id]} | {g.status} | {cell(g.detail)} |' for g in report.gates if g.status != 'SKIPPED']
    failing = [g for g in report.gates if g.status == 'FAIL']
    if failing:lines += ['', '不合格のゲートは下書きを止めないが、確定の前に直す。項目は `aws-design gate run --workspace WS --markdown` で見る。']
    for g in report.gates:
        if g.id == 'diagram_coverage':
            missing = [i for i in g.items if i.get('code') == 'PICTURE_SERVICE_NOT_IN_DESIGN']
            if missing:lines += ['', '構成図の画像にあって設計入力にないサービス：' + '、'.join(sorted({str(i.get('target')) for i in missing})) + '。']
    return lines


def asks_section(workspace, config):
    if not config.get('asks'):return ['判断の台帳を使わない設定。']
    from .asks import InputError as AsksError, STATES_JA, status
    try:found = status(workspace)
    except (AsksError, ValueError) as exc:return [f'判断の台帳を確かめられない：{str(exc)[:120]}']
    lines = [f"設計者の宿題 {found['designer_tasks']}件と構築時の注意 {found['build_notes']}件は人に聞かない（asks/tasks.md）。"]
    if found.get('counts'):lines.insert(0, '人に聞く判断：' + '、'.join(f'{STATES_JA.get(k, k)} {v}' for k, v in found['counts'].items()) + '。質問票は asks/batches/ にある。')
    elif found['next'] in ('DRAFT', 'FIX_LEDGER', 'CLASSIFY'):lines.insert(0, f"判断の台帳はまだ使える状態でない（{found['next']}）。")
    else:lines.insert(0, '人に聞く判断はない。')
    if found.get('unreviewed'):lines.append('台帳は検査を通したが、独立レビューは確定モードで行う。')
    return lines


def report(workspace):
    """The one page a person reads first: what the draft is, what it settled, what it did not look at, and what to ask."""
    from . import flow
    workspace = Path(workspace);config = flow.load(workspace)
    found = flow.runs(workspace);latest = found[-1] if found else None
    lines = ['# 下書きの報告', '',
             f"下書きモードの生成物（{latest.name if latest else 'まだ生成していない'}）。人の承認・合意・レビューはまだない。"
             '文書セット・方針パックの採用・概要の合意・レビューパックの判定は、確定モードで人が行う。', '',
             '## 1. 文書の仕分け', '', *sources_section(workspace), '',
             '## 2. 構成図と画像', '', *diagrams_section(workspace, config), '',
             '## 3. ゲート', '', *gates_section(latest), '',
             '## 4. 人への質問', '', *asks_section(workspace, config), '',
             '## 5. 確定モードへ', '',
             f'下書きを確かめたら `aws-design flow mode --workspace "{workspace}" --set final` で切り替える。'
             '仮の文書セットと未採用の方針パックは *.draft.json へ退き、承認者・採用者の判断待ちになる。'
             '構成図は2つ目の読み取りと独立レビュー、判断の台帳は独立レビュー、レビューパックはP1・P2の判定が加わる。']
    return '\n'.join(lines) + '\n'


def write_report(workspace):
    from . import flow
    found = flow.runs(workspace)
    if not found:return None
    path = found[-1] / REPORT
    path.write_text(report(workspace), encoding='utf-8')
    return path
