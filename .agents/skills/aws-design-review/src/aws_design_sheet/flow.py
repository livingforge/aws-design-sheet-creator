"""Design workflow: where a workspace stands and the one next step, read from its files.

A workspace holds flow.json (ARP root, environment, input, optional policy pack and trace)
and the files the steps write: sources/ (proposal, approved set), the input, runs/NNN
(generations, each with gates.json) and reviews/ (recorded verdicts). `status` reports each
stage and one next step of four kinds: a command `run all` performs itself (TODO), work for a
named agent with its handoff (WAITING_FOR_AGENT), a decision an approved delegation policy
lets `run all` record under an agent name (DELEGATED), or a decision for a person, returned
as a command with the role and never run (WAITING_FOR_PERSON, with the reasons the policy did
not cover it). There is no hidden state: deleting or editing a file changes the status.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .delegation import is_agent

CONFIG = 'flow.json'
ROLES = {'approver': '<承認者>', 'architect': '<合意者>', 'adopter': '<採用者>', 'reviewer': '<レビュー担当>'}
STATES = {'DONE': '完了', 'TODO': '未着手', 'WAITING_FOR_AGENT': 'エージェントの作業待ち', 'DELEGATED': '委任方針で自動判断できる',
          'WAITING_FOR_PERSON': '人の判断待ち', 'STALE': '更新が必要', 'SKIPPED': '対象外'}
OPEN = ('TODO', 'WAITING_FOR_AGENT', 'DELEGATED', 'WAITING_FOR_PERSON', 'STALE')


class InputError(ValueError):
    pass


class FlowConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    environment: str = Field(min_length=1)
    input: str = Field(min_length=1)
    arp_root: str | None = None
    policy_pack: str | None = None
    policy_input: str | None = None
    source_trace: str | None = None
    evaluate: bool = False
    overview: str | None = None
    asks: bool = False
    library: str | None = None
    people: dict[Literal['approver', 'architect', 'adopter', 'reviewer'], str] | None = None
    # draft: run all settles what a person would decide as a marked draft and asks nothing until the draft is out;
    # final: every decision goes to a person or the delegation policy. A flow.json without it is final.
    mode: Literal['draft', 'final'] = 'final'


def is_draft(config):return config.get('mode') == 'draft'


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest() if path and Path(path).is_file() else None


def load(workspace):
    path = Path(workspace) / CONFIG
    if not path.is_file():raise InputError(f'NO_WORKSPACE: {path} not found; run aws-design flow init')
    config = json.loads(path.read_text(encoding='utf-8'))
    for key in ('environment', 'input'):
        if not config.get(key):raise InputError(f'CONFIG_INCOMPLETE: {key}')
    try:FlowConfig.model_validate(config)
    except ValidationError as exc:
        raise InputError('CONTRACT_INVALID: flow.json ' + ', '.join('/'.join(map(str, e['loc'])) for e in exc.errors(include_input=False))) from None
    if any(is_agent(name) for name in (config.get('people') or {}).values()):raise InputError('PERSON_IS_AGENT: people are persons; agents act through the delegation policy')
    return config


def at(workspace, relative):return (Path(workspace) / relative) if relative else None


def runs(workspace):
    folder = Path(workspace) / 'runs'
    return sorted(p for p in folder.iterdir() if p.is_dir() and (p / 'summary.json').is_file()) if folder.is_dir() else []


def decisions(workspace):
    folder = Path(workspace) / 'reviews'
    return sorted(folder.glob('decisions-*.json')) if folder.is_dir() else []


def generation_input(workspace, config):
    return at(workspace, config['policy_input'] if config.get('policy_pack') else config['input'])


def fingerprint(workspace, config):
    """What a generation depends on; a run whose recorded fingerprint differs is stale."""
    found = decisions(workspace)
    printed = {'input': sha(generation_input(workspace, config)), 'source_set': sha(at(workspace, 'sources/set.json')),
               'source_trace': sha(at(workspace, config.get('source_trace'))), 'review_decisions': sha(found[-1]) if found else None,
               'system_overview': sha(at(workspace, config.get('overview')))}
    # The diagram ledger joins only workspaces that have one, so that earlier runs elsewhere stay current.
    from .diagram_ledger import ledger_files, single
    files = ledger_files(workspace)
    if files and single(workspace):printed['diagram_ledger'] = sha(files[0])
    elif files:printed['diagram_ledger'] = hashlib.sha256(json.dumps([[f.parent.name, sha(f)] for f in files]).encode()).hexdigest()
    return printed


def overview_stage(workspace, config, q):
    """The system overview must exist, load, carry no conflict and be agreed by a named person in its current form."""
    from .system_overview import InputError as OverviewError, check, load
    path = at(workspace, config['overview'])
    if not path.is_file():
        arp = config.get('arp_root')
        library = config.get('library')
        start = (f" --arp-root {q(arp)} --source-set {q(workspace / 'sources' / 'set.json')}" if arp else '') + ' [--template <ひな型>]' + (f' --library {q(library)}' if library else '')
        command = f"aws-design system init{start} --system-id <システムID> --name <名称> --output {q(path)}"
        return stage('overview', 'TODO', 'システム概要がない。' + ('ARP4の要件正本と、合えば典型構成のひな型から始め、作成担当エージェントに書かせる' if arp else
                     '典型構成のひな型（aws-design library list）から始めるか、aws-design system schema の形式で書く'), command)
    raw = path.read_bytes()
    try:report = check(load(raw))
    except (OverviewError, ValueError) as exc:
        return stage('overview', 'TODO', f'システム概要を読めない：{str(exc)[:200]}')
    codes = report['summary']['codes']
    detail = f"判定 {report['assessment']}" + (f"（{'、'.join(f'{k} {v}' for k, v in codes.items())}）" if codes else '')
    if report['assessment'] == 'CONFLICTS_FOUND':
        return stage('overview', 'TODO', 'システム概要に矛盾がある。' + detail + f' aws-design system check {q(path)} --output <新しいフォルダ> で内容を確かめて直す')
    if is_draft(config):
        # One draft is enough for a draft design; the second draft, the review and the agreement belong to the final mode.
        return stage('overview', 'DONE', '下書き（独立した2つ目の下書き・レビュー・合意は確定モードで行う）。' + detail)
    digest = sha(path)
    overview = load(raw)
    approval = workspace / 'sources' / f'overview-approval-{digest[:12]}.json'
    if approval.is_file() and json.loads(approval.read_text(encoding='utf-8')).get('overview_sha256') == digest:
        record = json.loads(approval.read_text(encoding='utf-8'))
        return stage('overview', 'DONE', f"合意者 {record['approver']}、" + detail)
    reviewed = None
    if overview.author is not None:
        from .autopilot import SECOND_DRAFT, overview_rule
        delegated_rule = overview_rule(workspace)
        second = workspace / SECOND_DRAFT
        if delegated_rule is not None and delegated_rule.require_second_draft and not second.is_file():
            # The delegation policy asks for an independent second draft to compare before agents may agree.
            return stage('overview', 'WAITING_FOR_AGENT', f"{overview.author.actor} が作成した概要。委任方針により、別の作成担当による独立した下書きが必要。" + detail,
                         agent=role('aws-design-author', 'overview-drafter', 1,
                                    {'start_from': 'aws-design system init の出力（要件だけの概要）', 'output': str(second),
                                     'actor': '最初の作成担当と異なる名前', 'must_not_read': str(path)}))
        record = workspace / 'sources' / f'overview-review-{digest[:12]}.json'
        reviewed = record.is_file() and json.loads(record.read_text(encoding='utf-8'))
        if not reviewed or reviewed.get('overview_sha256') != digest or reviewed.get('decision') != 'accepted':
            # A drafted overview goes to an independent reviewer before anyone agrees it.
            handoff = {'overview': str(path), 'output': str(record), 'actor': '作成担当と異なる名前'}
            if second.is_file():handoff['second_draft'] = str(second)
            return stage('overview', 'WAITING_FOR_AGENT', f"{overview.author.actor} が作成した概要。独立レビュー（aws-design-checker、overview-reviewer）の受理が必要。" + detail
                         + ('（レビューで差し戻し）' if reviewed and reviewed.get('decision') == 'rejected' else ''),
                         f"aws-design system review {q(path)} --decision accepted --actor <レビュー担当エージェント> --reason <確認した内容> --output {q(record)}",
                         agent=role('aws-design-checker', 'overview-reviewer', 1, handoff))
    command = f"aws-design system approve {q(path)} --approver <合意者> --output {q(approval)}"
    refused = ['NOT_DRAFTED_BY_AGENT']
    if reviewed:
        from .autopilot import plan_overview
        plan, refused = plan_overview(workspace, config, path, reviewed)
        if plan:return stage('overview', 'DELEGATED', '委任方針の条件を満たす。run all がエージェント名で合意を記録する。' + detail,
                             f'aws-design flow run all --workspace {q(workspace)}', delegation=plan)
    earlier = sorted((workspace / 'sources').glob('overview-approval-*.json')) if (workspace / 'sources').is_dir() else []
    if earlier:return stage('overview', 'STALE', '合意後にシステム概要が変わった。' + detail, command, '利用者が指名した合意者', refused=refused)
    return stage('overview', 'WAITING_FOR_PERSON', 'システム概要を関係者で確かめて合意する。' + detail, command, '利用者が指名した合意者', refused=refused)


# What each staleness of a ledger document means and who settles it: the worker re-reads, or ARP4 accepts a structure.
STALE_HELP = {
    'LEDGER_STALE': 'ARP4で文書が取り込み直された。view を取り直し、その文書の extraction_sha256 と全要素を読み直す',
    'STRUCTURE_STALE': 'ARP4で構造が受理し直された（古いのは台帳の側で、構造の再レビューは不要）。view を取り直し、'
                       'その文書の structure_content_hash と v: で始まる参照を新しい構造に合わせる',
    'LEDGER_NOT_CURRENT': '文書がCURRENTでなくなった。その文書を台帳から外す',
    'STRUCTURE_NOT_ACCEPTED': '画像に頼る要素がある文書のARP4構造レビューが未受理。作成担当ではなくARP4で、'
                              '範囲の描画（arp4 spec structure render）、vision読み取り、構造レビューの受理と保存を済ませてから作成担当に戻す',
}


def diagrams_stage(workspace, config, q):
    """Every drawing of the CURRENT documents read by two independent workers and the first reading reviewed, part by
    part: each document has its own readings and review, so one document is read again without the others."""
    from .diagram_ledger import (InputError as LedgerError, check, load, load_review, parts as find_parts, preflight,
                                 read_documents, sha as raw_sha, single)
    from .diagram_rules import by_rule
    arp, approved = config.get('arp_root'), workspace / 'sources' / 'set.json'
    if not arp or not approved.is_file():return stage('diagrams', 'SKIPPED', '承認済みの文書セットがない')
    try:drawings = read_documents(Path(arp), approved.read_bytes())
    except (LedgerError, ValueError) as exc:return stage('diagrams', 'TODO', f'文書の図形を読めない：{str(exc)[:200]}')
    documents = {d: len(found.elements) for d, found in drawings.items() if found.elements}
    found_parts = find_parts(workspace, drawings)
    if not documents and not any(p.first.is_file() for p in found_parts):return stage('diagrams', 'SKIPPED', 'CURRENTの文書に図形・画像がない')
    whole = single(workspace)
    if is_draft(config) and not whole:
        # A draft triages pictures first and reads only the documents that draw the system, once each.
        from .diagram_triage import flow_stage
        return flow_stage(workspace, config, q, drawings, approved)
    detail = f"図形・画像を含むCURRENTの文書 {len(documents)}件、要素 {sum(documents.values())}件"
    common = f'--arp-root {q(arp)} --source-set {q(approved)}'
    before = f'aws-design diagram preflight {common}'
    def scope(part):return ''.join(f' --for-document {q(d)}' for d in part.documents or [])
    def viewing(part):return f'aws-design diagram view {common}' + (f' --document {q(part.documents[0])}' if part.documents else '')
    def checking(part, path):return f'aws-design diagram check {common} --ledger {q(path)}' + scope(part)

    def state(part):
        """('runs', [worker runs]) | ('todo', why, command) | ('review', handoff) | ('done', ledger, review) for one part."""
        first, second = part.first, part.second
        label = {'document': part.documents[0]} if part.documents else {}
        def run(path, why, **more):return {**label, 'why': why, 'output': str(path), 'check': checking(part, path), 'view': viewing(part), **more}
        if not first.is_file() and not second.is_file():
            # Two independent readings at once: each run writes its own file and never reads the other's.
            return 'runs', [run(first, '構成図の台帳がない', actor='作成担当の名前'),
                            run(second, '独立した読み取りがない', actor='1つ目と異なる名前', must_not_read=str(first))]
        readings = []
        for path, actor in ((first, {'actor': '作成担当の名前'}), (second, {'actor': '最初の作成担当と異なる名前', 'must_not_read': str(first)})):
            if not path.is_file():
                return 'runs', [run(path, '構成図の台帳がない' if path == first else '別の作成担当による独立した読み取りがない', **actor)]
            try:ledger = load(path.read_bytes())
            except LedgerError as exc:return 'runs', [run(path, f'{path.name} が契約を満たさない（{str(exc)[:120]}）', **actor)]
            if by_rule(ledger):
                # A draft's rule reading is nobody's reading: a worker reads the drawings and puts its own name on the ledger.
                return 'runs', [run(path, f'{path.name} は下書きの規則による読み取り。作成担当が view で全要素を読み、処置を直して author を自分の名前にする', **actor)]
            found = check(ledger, drawings, part.documents)
            if found.status == 'FAIL':
                failing = {r['code'] for r in found.rows if r['severity'] == 'FAIL'}
                stale = {code: sorted({r['document'] for r in found.rows if r['code'] == code}) for code in STALE_HELP if code in failing}
                if 'STRUCTURE_NOT_ACCEPTED' in stale:
                    # Only ARP4 accepts a structure; sending the worker back would not change it.
                    why = f"{path.name}：{STALE_HELP['STRUCTURE_NOT_ACCEPTED']}（{'、'.join(stale['STRUCTURE_NOT_ACCEPTED'][:5])}）"
                    return 'todo', why, f'{before} --ledger {q(path)}'
                help_ = ''.join(f"{code}（{'、'.join(docs[:5])}）：{STALE_HELP[code]}。" for code, docs in stale.items())
                return 'runs', [run(path, f"{path.name} の検査が不合格：{'、'.join(sorted(failing))}。{help_}", **actor,
                                    **({'stale_documents': stale} if stale else {}))]
            readings.append(ledger)
        if readings[0].author.actor.strip() == readings[1].author.actor.strip():
            return 'runs', [run(second, '2つの読み取りが同じ作成担当による', actor='最初の作成担当と異なる名前', must_not_read=str(first))]
        digest = raw_sha(first.read_bytes());record = part.review(digest)
        reviewed = load_review(record.read_bytes()) if record.is_file() else None
        if reviewed is not None and reviewed.decision == 'rejected':
            return 'runs', [run(first, f'レビューで差し戻し（{reviewed.actor}：{reviewed.reason[:120]}）', actor=readings[0].author.actor)]
        if reviewed is None:
            return 'review', {**label, 'why': f'{readings[0].author.actor} の台帳', 'ledger': str(first), 'second_reading': str(second),
                              'compare': f'aws-design diagram compare --ledger {q(first)} --ledger {q(second)}', 'view': viewing(part),
                              'output': str(record), 'actor': '2人の作成担当と異なる名前',
                              'review': f'aws-design diagram review {common} --ledger {q(first)}{scope(part)} --decision accepted '
                                        f'--actor <レビュー担当エージェント> --reason <確認した内容> --output {q(record)}'}
        return 'done', readings[0], reviewed

    states = [(part, state(part)) for part in found_parts]
    done = [s for _, s in states if s[0] == 'done']
    progress = '' if whole else f'。部分台帳 {len(found_parts)}件のうち受理済み {len(done)}件'
    todo = next((s for _, s in states if s[0] == 'todo'), None)
    if todo:return stage('diagrams', 'TODO', f'{todo[1]}。' + detail + progress, todo[2])
    runs = [r for _, s in states if s[0] == 'runs' for r in s[1]]
    if runs:
        fresh = [part for part, s in states if s[0] == 'runs' and not part.first.is_file() and not part.second.is_file()]
        notes = []
        if fresh:
            # What the reading will need is known before it starts; a ledger that would outgrow its limit is not started.
            pre = preflight({d: f for d, f in drawings.items() if any(p.documents is None or d in p.documents for p in fresh)})
            over = any(f['code'] == 'DOCUMENT_OVER_LIMIT' or whole and f['code'] == 'SINGLE_LEDGER_OVER_LIMIT' for f in pre['findings'])
            if over:
                return stage('diagrams', 'TODO', f"台帳の推定サイズが上限 {pre['ledger_limit']}バイトを超える。"
                             '構成を描かない文書を文書セットから外してから読む。' + detail, before)
            unread = [f for f in pre['findings'] if f['code'] == 'PICTURE_WITHOUT_GRAPH']
            if unread:notes.append(f"作成担当を起動する前に：文字・代替テキスト・グラフのない画像 {sum(f['count'] for f in unread)}件（文書{len(unread)}件）を開き、"
                                   '構成を描くものはARP4で描画・vision読み取り・構造レビューを済ませる')
            if n := sum(f['code'] == 'STRUCTURE_NOT_ACCEPTED' for f in pre['findings']):notes.append(f'ARP4の構造レビューが未受理の文書 {n}件')
        base = {'preflight': before, 'arp_root': arp, 'source_set': str(approved)}
        if len(runs) == 1:
            why = runs[0].pop('why');handoff = {**base, **runs[0]}
        else:
            why = '構成図の台帳がない' if len(fresh) == len(found_parts) else f'作成担当の読み取り {len(runs)}件が必要'
            handoff = {**base, 'view': f'aws-design diagram view {common}', 'runs': runs}
        return stage('diagrams', 'WAITING_FOR_AGENT', f'{why}。' + detail + progress + ''.join(f'。{n}' for n in notes), runs[0]['check'],
                     agent=role('aws-design-author', 'diagram-extract-worker', len(runs), handoff))
    reviews = [s[1] for _, s in states if s[0] == 'review']
    if reviews:
        base = {'arp_root': arp, 'source_set': str(approved)}
        handoff = {**base, **{k: v for k, v in reviews[0].items() if k not in ('why', 'review')}} if len(reviews) == 1 else {**base, 'runs': reviews}
        why = f"{reviews[0]['why']}。" if len(reviews) == 1 else f'部分台帳 {len(reviews)}件。'
        return stage('diagrams', 'WAITING_FOR_AGENT', why + '独立レビュー（aws-design-checker、diagram-extract-reviewer）の受理が必要。' + detail + progress,
                     reviews[0]['review'], agent=role('aws-design-checker', 'diagram-extract-reviewer', len(reviews), handoff))
    unresolved = sum(e.disposition == 'UNRESOLVED' for _, ledger, _ in done for d in ledger.documents for e in d.elements)
    head = f'{done[0][1].author.actor} の台帳を {done[0][2].actor} が受理。' if whole else f'部分台帳 {len(done)}件すべてを独立レビューが受理。'
    return stage('diagrams', 'DONE', head + detail + (f'。UNRESOLVED {unresolved}件は判断の台帳で人に確かめる' if unresolved else ''))


def diagram_asks_missing(workspace):
    """Asks the diagram ledger's UNRESOLVED elements name that the asks ledger does not hold."""
    from .diagram_ledger import InputError as LedgerError, asks_state, ledger_files, load
    named = set()
    for path in ledger_files(workspace):
        try:ledger = load(path.read_bytes())
        except LedgerError:continue
        named |= {e.ask for d in ledger.documents for e in d.elements if e.disposition == 'UNRESOLVED'}
    if not named:return []
    held = asks_state(workspace)
    return sorted(a for a in named if a not in held)


def role(agent, name, count, handoff):
    """An agent run in a role: the role's instructions travel with the handoff, so two agents serve every role."""
    root = Path(__file__).resolve().parents[2]
    found = next((base / f'{name}.md' for base in (root / 'references' / 'roles', root / 'distribution' / 'roles')
                  if (base / f'{name}.md').is_file()), None)
    return {'name': agent, 'role': name, 'count': count,
            'handoff': {'role': name, 'instructions': str(found) if found else f'references/roles/{name}.md', **handoff}}


def stage(name, state, detail, command=None, person=None, *, agent=None, delegation=None, refused=None, action=None):
    """One stage row. `agent` is work for a named agent with its handoff; `delegation` the rule a DELEGATED step
    is recorded under; `refused` why a person's decision was not delegated; `action` what `run all` performs for a TODO."""
    row = {'stage': name, 'state': state, 'state_ja': STATES[state], 'detail': detail}
    if command:row['command'] = command
    if action:row['action'] = action
    if person:row['person'] = person
    if agent:row['agent'] = agent
    if delegation:row['delegation'] = {k: v for k, v in delegation.items() if k in ('rule', 'policy_sha256', 'action')}
    if refused and state in ('WAITING_FOR_PERSON', 'STALE'):row['delegation_refused'] = refused
    return row


def status(workspace):
    workspace = Path(workspace);config = load(workspace);stages = []
    q = lambda p: f'"{p}"'
    arp = config.get('arp_root')
    proposal, approved = workspace / 'sources' / 'proposal.json', workspace / 'sources' / 'set.json'
    draft = is_draft(config)
    from .draft_mode import is_draft_set
    if not arp:stages.append(stage('sources', 'SKIPPED', 'ARP4のルートが設定されていない'))
    elif not approved.is_file() and draft:
        # One step scans ARP4 and settles the set from that same scan, so nothing can change between the two.
        stages.append(stage('sources', 'TODO', '下書きモード：ARP4を走査して仮の文書セットを作る（未決の文書は規則で決め、人に聞かない）',
                            f'aws-design flow run all --workspace {q(workspace)}', action='draft-sources'))
    elif not approved.is_file() and not proposal.is_file():
        stages.append(stage('sources', 'TODO', '根拠文書セットの提案がない', f'aws-design flow run scan --workspace {q(workspace)}'))
    elif not draft and is_draft_set(approved):
        # A draft set is no approval: the final mode scans again and asks the approver.
        stages.append(stage('sources', 'STALE', '下書きで作った仮の文書セット。確定モードでは走査し直して承認者が承認する',
                            f'aws-design flow run scan --workspace {q(workspace)} --replace'))
    elif not approved.is_file():
        from .autopilot import plan_sources
        plan, refused = plan_sources(workspace, config)
        if plan:stages.append(stage('sources', 'DELEGATED', '提案に未決定・原本の問題がなく、委任方針の条件を満たす。run all がエージェント名で承認する',
                                    f'aws-design flow run all --workspace {q(workspace)}', delegation=plan))
        else:stages.append(stage('sources', 'WAITING_FOR_PERSON', '提案を承認者が確認する（aws-design sources show で表を出す）',
                                 f'aws-design sources approve --arp-root {q(arp)} --proposal {q(proposal)} --approver <承認者> [--set 文書ID=状態] --output {q(approved)}',
                                 '利用者が指名した承認者', refused=refused))
    else:
        from .source_set import check
        report = check(Path(arp), approved.read_bytes())
        if report['status'] == 'PASS' and is_draft_set(approved):stages.append(stage('sources', 'DONE', f"下書きの仮の文書セット、文書 {report['documents']}"))
        elif report['status'] == 'PASS':stages.append(stage('sources', 'DONE', f"承認者 {report['approval']['approver']}、文書 {report['documents']}"))
        elif draft:
            # A draft follows ARP4 by itself: the set is made again in one step and the old one is kept in sources/retired.
            codes = sorted({e['code'] for e in report['errors']})
            stages.append(stage('sources', 'STALE', '文書セットを作ったあとにARP4の文書が変わった：' + '、'.join(codes) + '。run all が走査し直して仮の文書セットを作り直す'
                                '（古いセットは sources/retired に残る。内容の変わらない文書の台帳と目視はそのまま使う）',
                                f'aws-design flow run all --workspace {q(workspace)}', action='draft-sources'))
        else:
            codes = sorted({e['code'] for e in report['errors']})
            stages.append(stage('sources', 'STALE', '承認後にARP4の文書が変わった：' + '、'.join(codes),
                                f'aws-design flow run scan --workspace {q(workspace)} --replace'))
    if config.get('overview'):stages.append(overview_stage(workspace, config, q))
    else:stages.append(stage('overview', 'SKIPPED', 'システム概要の指定なし'))
    stages.append(diagrams_stage(workspace, config, q))
    source_input = at(workspace, config['input'])
    if source_input.is_file():stages.append(stage('input', 'DONE', f"{config['input']}"))
    else:stages.append(stage('input', 'TODO', f"設計入力（1.1）がない。{source_input} に、CURRENTの文書だけから書くか、外部シートを aws-design external build で変換する"
                             + ('。概要の要件は aws-design system design-requirements で加える' if config.get('overview') else '')
                             + (f'。文書を読む：aws-design sources cells --arp-root {q(arp)} --source-set {q(approved)}（文書の一覧。--document 文書ID で全セルを引用に使うIDつきで、'
                                f'--grep 語 で語を含むセルを出す）。構成図：{workspace / "diagrams" / "parts"} の台帳と aws-design diagram view。'
                                '書き方：aws-design document --example（記入例）、aws-design document --types 語（カタログにある型）' if arp and approved.is_file() else
                                '。書き方：aws-design document --example（記入例）、aws-design document --types 語（カタログにある型）')))
    if config.get('policy_pack'):
        policy_input = at(workspace, config['policy_input'])
        command = (f"aws-design policy-pack apply {q(source_input)} --pack {config['policy_pack']}" + (f" --library {q(config['library'])}" if config.get('library') else '')
                   + f" --adopted-by <採用者> --output {q(policy_input)}")
        from .draft_mode import is_draft_policy_input
        if not policy_input.is_file() and draft:
            stages.append(stage('policy', 'TODO',
                                f"下書きモード：方針パック {config['policy_pack']} を未採用の候補（UNCONFIRMED）として適用する",
                                f'aws-design flow run all --workspace {q(workspace)}' if source_input.is_file() else None,
                                action='draft-policy' if source_input.is_file() else None))
        elif not draft and policy_input.is_file() and is_draft_policy_input(policy_input, config['policy_pack']):
            stages.append(stage('policy', 'STALE', '下書きで未採用の候補として適用した方針パック。確定モードでは採用者が採用する。'
                                '古いファイルを消して適用し直す', command, '利用者が指名した採用者'))
        elif not policy_input.is_file():
            from .autopilot import plan_policy
            plan, refused = plan_policy(workspace, config) if source_input.is_file() else (None, ['NO_INPUT'])
            if plan:stages.append(stage('policy', 'DELEGATED', f"方針パック {config['policy_pack']} は委任方針で採用できる。run all がエージェント名で採用する",
                                        f'aws-design flow run all --workspace {q(workspace)}', delegation=plan))
            else:stages.append(stage('policy', 'WAITING_FOR_PERSON', f"方針パック {config['policy_pack']} の採用者が必要", command, '利用者が指名した採用者', refused=refused))
        elif source_input.is_file() and policy_input.stat().st_mtime < source_input.stat().st_mtime:
            stages.append(stage('policy', 'STALE', '設計入力が方針パックの適用後に変わった。古いファイルを消して適用し直す', command, '利用者が指名した採用者'))
        else:stages.append(stage('policy', 'DONE', f"{config['policy_pack']} を適用済み"))
    else:stages.append(stage('policy', 'SKIPPED', '方針パックの指定なし'))
    found = runs(workspace);latest = found[-1] if found else None
    run_meta = json.loads((latest / 'flow-run.json').read_text(encoding='utf-8')) if latest and (latest / 'flow-run.json').is_file() else {}
    blocked = any(s['state'] in OPEN for s in stages)
    if latest is None:stages.append(stage('generate', 'TODO', '生成していない', None if blocked else f'aws-design flow run generate --workspace {q(workspace)}'))
    elif run_meta.get('fingerprint') != fingerprint(workspace, config):
        stages.append(stage('generate', 'STALE', f'{latest.name} の後に入力・文書セット・判定が変わった', None if blocked else f'aws-design flow run generate --workspace {q(workspace)}'))
    else:stages.append(stage('generate', 'DONE', f'{latest.name}（{run_meta.get("exit_code")}）'))
    generated = latest is not None and stages[-1]['state'] == 'DONE'
    stages.append(gates_stage(workspace, latest, q, draft) if generated else stage('gates', 'TODO', '最新の生成がない'))
    passed = generated and stages[-1]['state'] == 'DONE'
    if not config.get('asks'):stages.append(stage('asks', 'SKIPPED', '判断の台帳を使わない設定（flow.json の asks が false）'))
    elif passed:stages.append(asks_stage(workspace, config, q))
    else:stages.append(stage('asks', 'TODO', 'ゲートが合格していない' if generated else '最新の生成がない'))
    if draft:stages.append(stage('review', 'SKIPPED', '下書きモード：レビューパックは作るが、P1・P2の判定は確定モードで人が行う'))
    elif passed:stages.append(review_stage(workspace, config, latest, q))
    else:stages.append(stage('review', 'TODO', 'ゲートが合格していない' if generated else '最新の生成がない'))
    # Names the user registered for each role fill the commands; the decision guard still asks before they run.
    people = config.get('people') or {}
    for s in stages:
        for role, placeholder in ROLES.items():
            if people.get(role) and s.get('command'):s['command'] = s['command'].replace(placeholder, q(people[role]))
    nxt = next((s for s in stages if s['state'] in OPEN), None)
    if nxt:nxt = {**nxt, 'instruction': instruction(nxt, workspace, draft, q)}
    from .delegation import effective
    _, digest, suspended, problem = effective(workspace)
    return {'workspace': str(workspace), 'mode': config.get('mode', 'final'), 'stages': stages, 'next': nxt,
            'latest_run': latest.name if latest else None,
            **({'draft_ready': generated and nxt is None} if draft else {}),
            **({'draft_gates': draft_gates(workspace, latest, q)} if draft and generated and nxt is None and draft_gates(workspace, latest, q) else {}),
            'delegation': {'in_force': problem is None, 'problem': problem, 'policy_sha256': digest, 'suspended': sorted(suspended)},
            'notice': '完了はファイルがそろったことを表し、設計の承認ではない。人の判断待ちの手順はエージェントが代行しない。'
                      '委任方針で記録した判断はエージェント名と方針のハッシュを持ち、人の承認とは区別される。'}


def instruction(step, workspace, draft, q):
    """What the agent reading `next` does now, in one plain instruction: every state has exactly one."""
    again = f'aws-design flow run all --workspace {q(workspace)}'
    if step['state'] == 'WAITING_FOR_PERSON':
        return '止まる。command と担当（person）を利用者に見せ、利用者が指名した人の名前で実行する。自分の名前・仮の名前・試験用の名前では実行しない'
    agent = step.get('agent')
    if agent and agent['name'] == 'aws-design-review':
        return f'この作業は、この会話のあなた自身が行う（handoff の fix）。終えたら {again} を実行する'
    if agent:
        runs = f"{agent['count']}回（handoff の runs の1件ずつ。別々の actor 名で）" if agent['count'] > 1 else '1回'
        own = ('サブエージェントを起動できない環境では、handoff の instructions のファイルを読み、あなた自身がその役割を1件ずつ順に行ってよい（下書きモードに限る）。'
               if draft else '')
        return (f"エージェント {agent['name']}（役割 {agent['role']}）を {runs} 起動し、handoff をそのまま渡す。{own}"
                f'文書ID・出力先・文書セットのパスは handoff のとおりに使い、作り直したり別の場所に書いたりしない。終えたら {again} を実行する')
    if step.get('action') or step['state'] == 'DELEGATED' or step['stage'] in ('generate', 'gates') and step.get('command'):
        return f'{again} を実行する（この手順は run all が自分で行う。ほかのコマンドで代わりをしない）'
    if step['stage'] == 'input':
        return f'設計入力を書く（SKILL.md の「Write a design input from documents」）。書いたら {again} を実行する'
    if step.get('command'):return f"command を実行し、そのあと {again} を実行する"
    return f'detail のとおりに直し、そのあと {again} を実行する'


# A draft stops only where the draft itself is broken: a handover file that breaks its contract or a failed generation.
DRAFT_BLOCKING_GATES = ('contracts', 'generation')


# What a generation that stops on the input's structure says about it: passed on, so that nobody has to generate again to see it.
STRUCTURE_KEYS = ('error_count', 'messages', 'shape_errors')
# How many generations a draft spends on failing gates before it is handed over with them stated.
DRAFT_FIX_RUNS = 3


def draft_gates(workspace, latest, q):
    """What a finished draft says about gates that fail without stopping it: which, and whether to fix once more.
    `next` is null either way; without this an agent cannot tell a draft to hand over from one to fix."""
    if latest is None or not (latest / 'gates.json').is_file():return None
    from .gates import GATES_JA, load as load_gates
    failing = [g for g in load_gates(latest / 'gates.json').gates if g.status == 'FAIL']
    if not failing:return None
    again = len(runs(workspace)) < DRAFT_FIX_RUNS
    return {'failing': [g.id for g in failing], 'fix': again,
            'instruction': (f"下書きはできたが、ゲートが不合格（{'、'.join(GATES_JA[g.id] for g in failing)}）。"
                            + (f"aws-design gate run --workspace {q(workspace)} --markdown で項目を見て、設計入力を新しい写しで直し、"
                               f"aws-design flow input --workspace {q(workspace)} --set 新しい写し のあと aws-design flow run all をやり直す。"
                               f"生成は{DRAFT_FIX_RUNS}回までで切り上げる" if again else
                               f"生成を{len(runs(workspace))}回したので、ここで切り上げる。draft-report.md を渡し、不合格のゲートと残った項目を報告に書く"))}


def gates_stage(workspace, latest, q, draft=False):
    if not (latest / 'gates.json').is_file():
        return stage('gates', 'TODO', f'{latest.name} のゲートを評価していない', f'aws-design gate run --workspace {q(workspace)} --run {latest.name}')
    from .gates import GATES_JA, load as load_gates
    report = load_gates(latest / 'gates.json')
    failing = [g for g in report.gates if g.status == 'FAIL']
    if draft and failing and not any(g.id in DRAFT_BLOCKING_GATES for g in failing):
        return stage('gates', 'DONE', '下書き：不合格のゲートがある（確定の前に直す。draft-report.md に一覧）：'
                     + '、'.join(f'{GATES_JA[g.id]}（{g.detail}）' for g in failing))
    if failing:
        # Agents fix their handover; nothing downstream may be decided on a failing gate.
        return stage('gates', 'WAITING_FOR_AGENT', 'ゲート不合格：' + '、'.join(f'{GATES_JA[g.id]}（{g.detail}）' for g in failing)
                     + f'。aws-design gate run --workspace {q(workspace)} --markdown で項目を確かめ、入力の新しい写しで直す',
                     agent={'name': 'aws-design-review', 'count': 1, 'handoff': {'gates': str(latest / 'gates.json'), 'fix': 'flow.json が指す入力の新しい写し'}})
    return stage('gates', 'DONE', '、'.join(f'{GATES_JA[g.id]} {g.status}' for g in report.gates if g.status != 'SKIPPED'))


def asks_stage(workspace, config, q):
    """Decisions people still owe the design: classified, drafted, reviewed, asked in order, recorded and applied."""
    from .asks import InputError as AsksError, STATES_JA, status as asks_status
    try:report = asks_status(workspace)
    except (AsksError, ValueError) as exc:return stage('asks', 'TODO', f'判断の台帳を確かめられない：{str(exc)[:200]}')
    ledger = workspace / 'asks' / 'ledger.json'
    tail = f"人に聞かない項目：設計者の宿題 {report['designer_tasks']}件、構築時の注意 {report['build_notes']}件"
    counts = '、'.join(f'{STATES_JA[k]} {v}' for k, v in (report.get('counts') or {}).items())
    overdue = f"。期限切れ：{'、'.join(report['overdue'])}" if report.get('overdue') else ''
    nxt = report['next']
    grounding = {'arp_root': config.get('arp_root'), 'source_set': str(workspace / 'sources' / 'set.json')}
    if nxt == 'CLASSIFY':
        return stage('asks', 'WAITING_FOR_AGENT', f"未決の設定 {report['unclassified']}件に原因（cause）か判断（ask）が書かれていない。設計入力の新しい写しで書き足す",
                     agent={'name': 'aws-design-review', 'count': 1,
                            'handoff': {'fix': 'UNDECIDED の各設定に cause、OWNER_DECISION・WAITS_FOR・EXTERNAL_DATA には ask も書いた入力の新しい写し（flow.json を向ける）',
                                        'list': f'aws-design asks start --workspace {q(workspace)}'}})
    missing = diagram_asks_missing(workspace)
    if nxt == 'NOTHING_TO_ASK' and not missing:return stage('asks', 'DONE', '人に聞く判断はない。' + tail)
    if nxt in ('DRAFT', 'FIX_LEDGER') or missing and nxt != 'REVIEW':
        if missing and nxt not in ('DRAFT', 'FIX_LEDGER'):why = '構成図の UNRESOLVED 要素の判断が台帳にない：' + '、'.join(missing[:10])
        else:why = '判断の台帳がない' if nxt == 'DRAFT' else ('レビューで差し戻し：' + report['rejected'] if report.get('rejected') else
                                                    '台帳の検査が不合格：' + '、'.join(sorted({f['code'] for f in report.get('findings', [])})))
        return stage('asks', 'WAITING_FOR_AGENT', f"{why}。作成担当エージェントが判断ごとに問い・背景・選択肢を書く。" + tail,
                     agent=role('aws-design-author', 'ask-drafter', 1,
                                {'start': f'aws-design asks start --workspace {q(workspace)}', 'output': str(ledger),
                                 'check': f'aws-design asks check --workspace {q(workspace)}', **grounding, 'actor': '作成担当の名前'}))
    if nxt == 'REVIEW':
        return stage('asks', 'WAITING_FOR_AGENT', f"{report.get('author') or '作成担当'} が書いた判断の台帳。独立レビュー（aws-design-checker、ask-reviewer）の受理が必要",
                     f"aws-design asks review --workspace {q(workspace)} --decision accepted --actor <レビュー担当エージェント> --reason <確認した内容>",
                     agent=role('aws-design-checker', 'ask-reviewer', 1, {'ledger': str(ledger), **grounding, 'actor': '作成担当と異なる名前'}))
    if nxt == 'APPLY':
        return stage('asks', 'TODO', f'回答済みの判断を設計入力の新しい写しへ反映する（{counts}）', f'aws-design asks apply --workspace {q(workspace)}', action='apply')
    if nxt == 'SHEET':
        return stage('asks', 'TODO', f'聞ける判断を順番に、宛先ごとの質問票と会議の議題にする（{counts}）{overdue}',
                     f'aws-design asks sheet --workspace {q(workspace)}', action='sheet')
    unreviewed = '（下書き：台帳の独立レビューは確定モードで行う）' if report.get('unreviewed') else ''
    if nxt == 'WAIT_FOR_ANSWERS' and is_draft(config):
        # The draft is out; answers improve it later and never hold it back.
        return stage('asks', 'DONE', f'質問票（asks/batches）を作成済み。回答待ちだが下書きは止めない（{counts}）{overdue}{unreviewed}。'
                     '回答は --dry-run で言い換えを確かめてから記録する。' + tail)
    if nxt == 'WAIT_FOR_ANSWERS':
        return stage('asks', 'WAITING_FOR_PERSON', f'質問票（asks/batches）の回答待ち（{counts}）{overdue}。回答は --dry-run で言い換えを確かめてから記録する',
                     f'aws-design asks record --workspace {q(workspace)} --workbook <回答済みの質問票>', '質問票の宛先（回答者の名前は質問票に書く）')
    return stage('asks', 'DONE', f'{counts or "判断なし"}{overdue}。{tail}')


def review_stage(workspace, config, latest, q):
    pack_data = json.loads((latest / 'review-pack.json').read_text(encoding='utf-8'))
    pack = pack_data['summary']['priorities']
    if pack['P1'] + pack['P2'] == 0:return stage('review', 'DONE', f"P1・P2なし（前回確認済み {pack['DONE']}）")
    from .autopilot import plan_review
    plan, refused = plan_review(workspace, latest, pack_data)
    counts = f"P1 {pack['P1']}件・P2 {pack['P2']}件。"
    if plan and plan['action'] == 'agents':
        folder = latest / 'agent-review'
        return stage('review', 'WAITING_FOR_AGENT', counts + f"委任方針により P2 の {plan['rows']}行を独立したレビュー担当エージェント {plan['reviewers']}体が判定する"
                     f"（あと {plan['reviewers'] - plan['have']}体）",
                     agent=role('aws-design-checker', 'review-pack-checker', plan['reviewers'] - plan['have'],
                                {'packet': str(folder / 'packet.json'), 'output': str(folder / 'verdicts-<actor>.json'),
                                 'arp_root': config.get('arp_root'), 'source_set': str(workspace / 'sources' / 'set.json'),
                                 'actor': '他のレビュー担当と異なる名前'}), delegation=plan)
    if plan:
        what = '検出用の行を混ぜた判定用パケットを作る' if plan['action'] == 'packet' else 'エージェントの判定を突き合わせ、全員がOKとした行だけを記録する'
        return stage('review', 'DELEGATED', counts + f'委任方針により run all が{what}', f'aws-design flow run all --workspace {q(workspace)}', delegation=plan)
    previous = decisions(workspace)
    output = workspace / 'reviews' / f'decisions-{latest.name}.json'
    command = (f"aws-design review-pack record --workbook {q(latest / 'review-pack.xlsx')} --reviewer <レビュー担当> "
               + (f"--previous {q(previous[-1])} " if previous else '') + f"--output {q(output)}")
    return stage('review', 'WAITING_FOR_PERSON', counts + f"レビュー担当が {latest.name}/review-pack.xlsx に OK／NG を書く",
                 command, '利用者が指名したレビュー担当', refused=refused)


def render(report):
    lines = ['| 段階 | 状態 | 内容 |', '|---|---|---|']
    lines += [f"| {s['stage']} | {s['state_ja']} | {s['detail']} |" for s in report['stages']]
    n = report['next']
    lines += ['', '次：' + (f"{n['stage']}（{n['state_ja']}）" + (f"\n\nすること：{n['instruction']}" if n.get('instruction') else '') +
                         (f"\n\n    {n['command']}" if n.get('command') else '') +
                         (f"\n\n担当：{n['person']}" if n.get('person') else '') +
                         (f"\n\nエージェント：{n['agent']['name']} ×{n['agent']['count']}（" + '、'.join(f'{k}={v}' for k, v in n['agent']['handoff'].items() if k != 'runs') + '）'
                          + ''.join(f"\n- {i}：" + '、'.join(f'{k}={v}' for k, v in run.items()) for i, run in enumerate(n['agent']['handoff'].get('runs', []), 1))
                          if n.get('agent') else '') +
                         (f"\n\n委任されない理由：{'、'.join(n['delegation_refused'])}" if n.get('delegation_refused') else '') if n else 'なし'),
              *(['', 'すること：' + report['draft_gates']['instruction']] if report.get('draft_gates') else []), '', report['notice']]
    return '\n'.join(lines) + '\n'


def retire_sources(workspace, names=('proposal.json', 'set.json')):
    """Move the proposal and the set out of use into sources/retired under the time, never over an earlier file. The
    flow reads only sources/set.json; nothing in retired/ is ever read again."""
    from datetime import datetime, timezone
    folder = Path(workspace) / 'sources';moved = []
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    for name in names:
        if not (folder / name).is_file():continue
        target = folder / 'retired' / f'{stamp}-{name}';n = 1
        while target.exists():n += 1;target = folder / 'retired' / f'{stamp}-{n}-{name}'
        target.parent.mkdir(parents=True, exist_ok=True);(folder / name).replace(target);moved.append(str(target))
    return moved


def run_scan(workspace, replace=False):
    from .fileio import write_atomic
    from .source_set import dump, scan
    config = load(workspace)
    if not config.get('arp_root'):raise InputError('NO_ARP_ROOT')
    folder = Path(workspace) / 'sources';folder.mkdir(exist_ok=True)
    retired = retire_sources(workspace) if replace else []
    if (folder / 'proposal.json').exists():raise InputError('proposal already exists; approve it or run with --replace')
    proposal = scan(Path(config['arp_root']))
    write_atomic(folder / 'proposal.json', dump(proposal.model_dump()))
    return {'proposal': str(folder / 'proposal.json'), 'undecided': [e.document_id for e in proposal.documents if e.status == 'UNDECIDED'],
            **({'retired': retired} if retired else {})}


def run_all(workspace, limit=16):
    """Perform every step that needs neither a person nor an agent's work: scans, generation, gates and
    the decisions an approved delegation policy covers. Stops at the first step that needs someone."""
    from . import draft_mode
    done = []
    for _ in range(limit):
        nxt = status(workspace)['next']
        if nxt is None:break
        if nxt.get('action') == 'draft-sources':done.append(draft_mode.do_sources(workspace, load(workspace)))
        elif nxt.get('action') == 'draft-policy':done.append(draft_mode.do_policy(workspace, load(workspace)))
        elif nxt.get('action') == 'triage':
            from .diagram_triage import build
            done.append(build(workspace))
        elif nxt.get('action') == 'read-diagrams':
            from .diagram_rules import InputError as RuleError, write_missing
            try:done.append(write_missing(workspace))
            except RuleError as exc:raise InputError(str(exc)) from None
        elif nxt['stage'] == 'sources' and nxt['state'] in ('TODO', 'STALE'):
            result = run_scan(workspace, replace=nxt['state'] == 'STALE');done.append({'step': 'scan', 'undecided': result['undecided']})
        elif nxt['state'] == 'DELEGATED':done.append(delegated(workspace, nxt))
        elif nxt['stage'] == 'generate' and nxt.get('command'):
            code, output, result = run_generate(workspace)
            done.append({'step': 'generate', 'run': output.name, 'exit_code': code, 'generation_status': result.get('generation_status'),
                         'gates': result.get('gates'), **{k: result[k] for k in STRUCTURE_KEYS if k in result}})
            if code == 2:break
        elif nxt['stage'] == 'asks' and nxt['state'] == 'TODO' and nxt.get('action'):
            from . import asks
            result = asks.make_sheets(workspace) if nxt['action'] == 'sheet' else asks.apply(workspace)
            done.append({'step': f"asks-{nxt['action']}", **{k: result[k] for k in ('batch', 'sheets', 'agenda', 'input', 'applied') if k in result}})
        elif nxt['stage'] == 'gates' and nxt.get('command'):
            from .gates import write
            latest = runs(workspace)[-1]
            done.append({'step': 'gates', 'run': latest.name, 'status': write(workspace, latest.name).status})
        else:break
    if is_draft(load(workspace)) and (path := draft_mode.write_report(workspace)):done.append({'step': 'draft-report', 'report': str(path)})
    return done


def delegated(workspace, step):
    """Record one DELEGATED decision; the plan is computed again so nothing stale is recorded."""
    try:return record_delegated(workspace, step)
    except InputError:raise
    except ValidationError as exc:
        # An agent's file broke its contract: name the location so the agent can fix it, never the values.
        raise InputError('DELEGATION_INPUT_INVALID: ' + ', '.join('/'.join(map(str, e['loc'])) + ' ' + e['type'] for e in exc.errors(include_input=False))[:300]) from None
    except ValueError as exc:raise InputError('DELEGATION_REFUSED: ' + str(exc).split(':', 1)[0][:120]) from None


def record_delegated(workspace, step):
    from . import autopilot
    workspace = Path(workspace);config = load(workspace)
    refused = ['UNKNOWN_STAGE']
    if step['stage'] == 'sources':
        plan, refused = autopilot.plan_sources(workspace, config)
        if plan:return autopilot.do_sources(workspace, config, plan)
    elif step['stage'] == 'policy':
        plan, refused = autopilot.plan_policy(workspace, config)
        if plan:return autopilot.do_policy(workspace, config, plan, at(workspace, config['input']), at(workspace, config['policy_input']))
    elif step['stage'] == 'overview':
        path = at(workspace, config['overview']);digest = sha(path)
        review = json.loads((workspace / 'sources' / f'overview-review-{digest[:12]}.json').read_text(encoding='utf-8'))
        plan, refused = autopilot.plan_overview(workspace, config, path, review)
        if plan:return autopilot.do_overview(workspace, config, plan, path, workspace / 'sources' / f'overview-approval-{digest[:12]}.json')
    elif step['stage'] == 'review':
        latest = runs(workspace)[-1]
        plan, refused = autopilot.plan_review(workspace, latest, json.loads((latest / 'review-pack.json').read_text(encoding='utf-8')))
        if plan and plan['action'] == 'packet':return autopilot.do_packet(workspace, latest, plan)
        if plan and plan['action'] == 'agree':return autopilot.do_agree(workspace, latest, plan)
    raise InputError('DELEGATION_NOT_APPLICABLE: ' + '、'.join(refused or []))


def run_generate(workspace):
    from .document_cli import main as generate
    workspace = Path(workspace);config = load(workspace)
    found = runs(workspace)
    number = int(found[-1].name) + 1 if found and found[-1].name.isdigit() else 1
    output = workspace / 'runs' / f'{number:03d}'
    args = [str(generation_input(workspace, config)), '--environment', config['environment'], '--output', str(output)]
    if (workspace / 'sources' / 'set.json').is_file():args += ['--source-set', str(workspace / 'sources' / 'set.json'), '--arp-root', config['arp_root']]
    if config.get('source_trace'):args += ['--source-trace', str(at(workspace, config['source_trace']))]
    if decisions(workspace):args += ['--review-decisions', str(decisions(workspace)[-1])]
    if config.get('evaluate'):args.append('--evaluate')
    overview = at(workspace, config.get('overview'))
    if overview and overview.is_file():args += ['--system-overview', str(overview)]
    (workspace / 'runs').mkdir(exist_ok=True)
    import contextlib
    import io
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):code = generate(args)
    lines = printed.getvalue().strip().splitlines()
    result = json.loads(lines[-1]) if lines else {}
    if output.is_dir():
        (output / 'flow-run.json').write_text(json.dumps({'fingerprint': fingerprint(workspace, config), 'exit_code': code, 'arguments': args},
                                                         ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        if (output / 'review-pack.json').is_file():
            from .gates import write
            result['gates'] = write(workspace, output.name).status
    return code, output, result


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design flow', description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('init', help='create flow.json in a workspace folder');p.add_argument('--workspace', required=True)
    p.add_argument('--environment', required=True);p.add_argument('--input', default='input/design.json')
    p.add_argument('--arp-root');p.add_argument('--policy-pack');p.add_argument('--source-trace');p.add_argument('--evaluate', action='store_true')
    p.add_argument('--overview', action='store_true', help='agree a system overview (input/system-overview.json) before the design input')
    p.add_argument('--no-asks', dest='asks', action='store_false', help='do not ask people the open decisions through an asks ledger (asks/)')
    p.add_argument('--library', help='organisation library folder (dictionary, policy packs, overview templates)')
    p.add_argument('--mode', choices=['draft', 'final'], default='draft',
                   help='draft (default): settle what a person would decide as a marked draft and ask only after the draft is out; '
                        'final: every decision goes to a person or the delegation policy')

    def role_args(p):
        p.add_argument('--approver', help='source-set approver the user names');p.add_argument('--architect', help='system-overview agreer the user names')
        p.add_argument('--adopter', help='policy-pack adopter the user names');p.add_argument('--reviewer', help='review-pack reviewer the user names')
    role_args(p)
    p = sub.add_parser('people', help='register the people the user names for each role');p.add_argument('--workspace', required=True);role_args(p)
    p = sub.add_parser('mode', help='switch between draft and final; to final, the draft source set and candidate policy input go aside')
    p.add_argument('--workspace', required=True);p.add_argument('--set', dest='mode', required=True, choices=['draft', 'final'])
    p = sub.add_parser('input', help='point the workspace at a design input: a new copy you wrote after fixing the earlier one')
    p.add_argument('--workspace', required=True);p.add_argument('--set', dest='path', required=True, help='the input file, inside the workspace')
    p = sub.add_parser('draft-report', help='print the draft report (draft-report.md) of the workspace as it stands')
    p.add_argument('--workspace', required=True)
    p = sub.add_parser('inbox', help='one workbook with every decision the workspace waits for');p.add_argument('--workspace', required=True)
    p.add_argument('--output', required=True, help='fresh folder')
    p = sub.add_parser('decide', help='record the decisions written in an inbox workbook, by the people named there or registered')
    p.add_argument('--workspace', required=True);p.add_argument('--workbook', required=True)
    p = sub.add_parser('status', help='each stage and the next step');p.add_argument('--workspace', required=True)
    p.add_argument('--markdown', action='store_true')
    p = sub.add_parser('run', help='perform steps that need no person: scan, generate, or all until a person is needed')
    p.add_argument('step', choices=['scan', 'generate', 'all'])
    p.add_argument('--workspace', required=True);p.add_argument('--replace', action='store_true', help='scan again, keeping the old files in sources/retired')
    args = parser.parse_args(argv)
    try:
        workspace = Path(args.workspace)
        if args.command == 'init':
            if (workspace / CONFIG).exists():raise InputError('flow.json already exists')
            workspace.mkdir(parents=True, exist_ok=True)
            # The folder the input is written to exists from the start, so the first write does not fail on it.
            (workspace / args.input).parent.mkdir(parents=True, exist_ok=True)
            if args.asks:(workspace / 'asks').mkdir(exist_ok=True)
            if any(is_agent(getattr(args, r)) for r in ROLES if getattr(args, r)):raise InputError('PERSON_IS_AGENT: register persons only')
            config = {'environment': args.environment, 'input': args.input, 'arp_root': args.arp_root, 'policy_pack': args.policy_pack,
                      'policy_input': 'input/design-with-policies.json' if args.policy_pack else None,
                      'source_trace': args.source_trace, 'evaluate': args.evaluate,
                      'overview': 'input/system-overview.json' if args.overview else None, 'asks': args.asks, 'library': args.library,
                      'people': {r: getattr(args, r).strip() for r in ROLES if getattr(args, r) and getattr(args, r).strip()} or None,
                      'mode': args.mode}
            (workspace / CONFIG).write_text(json.dumps({k: v for k, v in config.items() if v not in (None, False)}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            print(json.dumps({'workspace': str(workspace), 'mode': args.mode, 'next': status(workspace)['next']}, ensure_ascii=False));return 0
        if args.command == 'mode':
            from .draft_mode import switch
            result = switch(workspace, args.mode)
            print(json.dumps({**result, 'next': status(workspace)['next']}, ensure_ascii=False));return 0
        if args.command == 'input':
            config = load(workspace)
            target = Path(args.path) if Path(args.path).is_absolute() else workspace / args.path
            try:relative = target.resolve().relative_to(workspace.resolve()).as_posix()
            except ValueError:raise InputError(f'INPUT_OUTSIDE_WORKSPACE: {target} is not inside {workspace}') from None
            if not target.is_file():raise InputError(f'NO_INPUT: {target} does not exist; write the input first')
            from .contracts import validate
            found = validate(target, 'design-input')
            previous = config['input'];config['input'] = relative
            (workspace / CONFIG).write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            print(json.dumps({'input': relative, 'previous': previous, 'contract': found['status'], **({'errors': found['errors'][:20]} if found['errors'] else {}),
                              'next': status(workspace)['next']}, ensure_ascii=False));return 0
        if args.command == 'draft-report':
            from .draft_mode import report as draft_report
            load(workspace);sys.stdout.buffer.write(draft_report(workspace).encode('utf-8'));return 0
        if args.command == 'status':
            report = status(workspace)
            text = render(report) if args.markdown else json.dumps(report, ensure_ascii=False, indent=2) + '\n'
            sys.stdout.buffer.write(text.encode('utf-8'));return 0
        if args.command == 'people':
            if any(is_agent(getattr(args, r)) for r in ROLES if getattr(args, r)):raise InputError('PERSON_IS_AGENT: register persons only')
            config = load(workspace)
            config['people'] = {**(config.get('people') or {}), **{r: getattr(args, r).strip() for r in ROLES if getattr(args, r) and getattr(args, r).strip()}}
            (workspace / CONFIG).write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            print(json.dumps({'people': config['people']}, ensure_ascii=False));return 0
        if args.command == 'inbox':
            from .inbox import make, workbook
            out = Path(args.output)
            if out.exists():raise InputError('output already exists; use a fresh folder')
            made = make(workspace);out.mkdir(parents=True)
            book = workbook(made);book.save(out / 'inbox.xlsx');book.close()
            (out / 'inbox.json').write_text(json.dumps(made, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            print(json.dumps({'inbox': str(out / 'inbox.xlsx'), 'rows': len(made['rows']), 'by_kind': made['summary']}, ensure_ascii=False));return 0
        if args.command == 'decide':
            from .inbox import InputError as InboxError, decide
            try:done = decide(workspace, args.workbook)
            except InboxError as exc:raise InputError(str(exc)) from None
            print(json.dumps({'recorded': done, 'next': status(workspace)['next']}, ensure_ascii=False));return 0
        if args.step == 'all':
            done = run_all(workspace)
            after = status(workspace)
            print(json.dumps({'done': done, 'next': after['next'], **({'draft_gates': after['draft_gates']} if after.get('draft_gates') else {})}, ensure_ascii=False))
            return 2 if done and done[-1].get('exit_code') == 2 else 0
        if args.step == 'scan':
            print(json.dumps(run_scan(workspace, args.replace), ensure_ascii=False));return 0
        code, output, result = run_generate(workspace)
        brief = {k: result[k] for k in ('generation_status', 'errors', 'review_pack', 'source_set_status', 'input_completeness', 'gates', *STRUCTURE_KEYS) if k in result}
        print(json.dumps({'run': str(output), 'exit_code': code, **brief, 'next': status(workspace)['next']}, ensure_ascii=False));return code
    except (InputError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc) if isinstance(exc, InputError) else type(exc).__name__}, ensure_ascii=False));return 2


if __name__ == '__main__':
    raise SystemExit(main())
