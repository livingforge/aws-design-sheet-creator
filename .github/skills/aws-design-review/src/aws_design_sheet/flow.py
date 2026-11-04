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
    from .diagram_ledger import ledger_path
    if ledger_path(workspace).is_file():printed['diagram_ledger'] = sha(ledger_path(workspace))
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


def diagrams_stage(workspace, config, q):
    """Every drawing of the CURRENT documents read by two independent workers, and the first reading reviewed."""
    from .diagram_ledger import (InputError as LedgerError, LedgerReview, check, ledger_path, load, read_documents, review_path,
                                 second_path, sha as raw_sha)
    arp, approved = config.get('arp_root'), workspace / 'sources' / 'set.json'
    if not arp or not approved.is_file():return stage('diagrams', 'SKIPPED', '承認済みの文書セットがない')
    try:drawings = read_documents(Path(arp), approved.read_bytes())
    except (LedgerError, ValueError) as exc:return stage('diagrams', 'TODO', f'文書の図形を読めない：{str(exc)[:200]}')
    documents = {d: len(found.elements) for d, found in drawings.items() if found.elements}
    first, second = ledger_path(workspace), second_path(workspace)
    if not documents and not first.is_file():return stage('diagrams', 'SKIPPED', 'CURRENTの文書に図形・画像がない')
    detail = f"図形・画像を含むCURRENTの文書 {len(documents)}件、要素 {sum(documents.values())}件"
    view = f'aws-design diagram view --arp-root {q(arp)} --source-set {q(approved)}'
    def checking(path):return f'aws-design diagram check --arp-root {q(arp)} --source-set {q(approved)} --ledger {q(path)}'
    def worker(path, why, **more):
        return stage('diagrams', 'WAITING_FOR_AGENT', why + detail, checking(path),
                     agent=role('aws-design-author', 'diagram-extract-worker', 1,
                                {'view': view, 'output': str(path), 'check': checking(path), 'arp_root': arp, 'source_set': str(approved), **more}))
    if not first.is_file() and not second.is_file():
        # Two independent readings at once: each run writes its own file and never reads the other's.
        return stage('diagrams', 'WAITING_FOR_AGENT', '構成図の台帳がない。' + detail, checking(first),
                     agent=role('aws-design-author', 'diagram-extract-worker', 2,
                                {'view': view, 'arp_root': arp, 'source_set': str(approved),
                                 'runs': [{'output': str(first), 'check': checking(first), 'actor': '作成担当の名前'},
                                          {'output': str(second), 'check': checking(second), 'actor': '1つ目と異なる名前', 'must_not_read': str(first)}]}))
    readings = []
    for path, actor in ((first, {'actor': '作成担当の名前'}), (second, {'actor': '最初の作成担当と異なる名前', 'must_not_read': str(first)})):
        if not path.is_file():
            return worker(path, '構成図の台帳がない。' if path == first else '別の作成担当による独立した読み取りがない。', **actor)
        try:ledger = load(path.read_bytes())
        except LedgerError as exc:return worker(path, f'{path.name} が契約を満たさない（{str(exc)[:120]}）。', **actor)
        found = check(ledger, drawings)
        if found.status == 'FAIL':
            return worker(path, f"{path.name} の検査が不合格：{'、'.join(sorted({r['code'] for r in found.rows if r['severity'] == 'FAIL'}))}。", **actor)
        readings.append(ledger)
    if readings[0].author.actor.strip() == readings[1].author.actor.strip():
        return worker(second, '2つの読み取りが同じ作成担当による。', actor='最初の作成担当と異なる名前', must_not_read=str(first))
    digest = raw_sha(first.read_bytes());record = review_path(workspace, digest)
    reviewed = LedgerReview.model_validate_json(record.read_bytes()) if record.is_file() else None
    if reviewed is not None and reviewed.decision == 'rejected':
        return worker(first, f'レビューで差し戻し（{reviewed.actor}：{reviewed.reason[:120]}）。', actor=readings[0].author.actor)
    if reviewed is None:
        compare = f'aws-design diagram compare --ledger {q(first)} --ledger {q(second)}'
        return stage('diagrams', 'WAITING_FOR_AGENT', f'{readings[0].author.actor} の台帳。独立レビュー（aws-design-checker、diagram-extract-reviewer）の受理が必要。' + detail,
                     f'aws-design diagram review --arp-root {q(arp)} --source-set {q(approved)} --ledger {q(first)} --decision accepted '
                     f'--actor <レビュー担当エージェント> --reason <確認した内容> --output {q(record)}',
                     agent=role('aws-design-checker', 'diagram-extract-reviewer', 1,
                                {'ledger': str(first), 'second_reading': str(second), 'compare': compare, 'view': view, 'output': str(record),
                                 'arp_root': arp, 'source_set': str(approved), 'actor': '2人の作成担当と異なる名前'}))
    unresolved = sum(e.disposition == 'UNRESOLVED' for d in readings[0].documents for e in d.elements)
    return stage('diagrams', 'DONE', f'{readings[0].author.actor} の台帳を {reviewed.actor} が受理。' + detail
                 + (f'。UNRESOLVED {unresolved}件は判断の台帳で人に確かめる' if unresolved else ''))


def diagram_asks_missing(workspace):
    """Asks the diagram ledger's UNRESOLVED elements name that the asks ledger does not hold."""
    from .diagram_ledger import InputError as LedgerError, asks_state, ledger_path, load
    if not ledger_path(workspace).is_file():return []
    try:ledger = load(ledger_path(workspace).read_bytes())
    except LedgerError:return []
    held = asks_state(workspace)
    return sorted({e.ask for d in ledger.documents for e in d.elements if e.disposition == 'UNRESOLVED' and e.ask not in held})


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
    if not arp:stages.append(stage('sources', 'SKIPPED', 'ARP4のルートが設定されていない'))
    elif not approved.is_file() and not proposal.is_file():
        stages.append(stage('sources', 'TODO', '根拠文書セットの提案がない', f'aws-design flow run scan --workspace {q(workspace)}'))
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
        if report['status'] == 'PASS':stages.append(stage('sources', 'DONE', f"承認者 {report['approval']['approver']}、文書 {report['documents']}"))
        else:
            codes = sorted({e['code'] for e in report['errors']})
            stages.append(stage('sources', 'STALE', '承認後にARP4の文書が変わった：' + '、'.join(codes),
                                f'aws-design flow run scan --workspace {q(workspace)} --replace'))
    if config.get('overview'):stages.append(overview_stage(workspace, config, q))
    else:stages.append(stage('overview', 'SKIPPED', 'システム概要の指定なし'))
    stages.append(diagrams_stage(workspace, config, q))
    source_input = at(workspace, config['input'])
    if source_input.is_file():stages.append(stage('input', 'DONE', f"{config['input']}"))
    else:stages.append(stage('input', 'TODO', '設計入力（1.1）がない。CURRENTの文書だけから書くか、外部シートを aws-design external build で変換する'
                             + ('。概要の要件は aws-design system design-requirements で加える' if config.get('overview') else '')))
    if config.get('policy_pack'):
        policy_input = at(workspace, config['policy_input'])
        command = (f"aws-design policy-pack apply {q(source_input)} --pack {config['policy_pack']}" + (f" --library {q(config['library'])}" if config.get('library') else '')
                   + f" --adopted-by <採用者> --output {q(policy_input)}")
        if not policy_input.is_file():
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
    stages.append(gates_stage(workspace, latest, q) if generated else stage('gates', 'TODO', '最新の生成がない'))
    passed = generated and stages[-1]['state'] == 'DONE'
    if not config.get('asks'):stages.append(stage('asks', 'SKIPPED', '判断の台帳を使わない設定（flow.json の asks が false）'))
    elif passed:stages.append(asks_stage(workspace, config, q))
    else:stages.append(stage('asks', 'TODO', 'ゲートが合格していない' if generated else '最新の生成がない'))
    if passed:stages.append(review_stage(workspace, config, latest, q))
    else:stages.append(stage('review', 'TODO', 'ゲートが合格していない' if generated else '最新の生成がない'))
    # Names the user registered for each role fill the commands; the decision guard still asks before they run.
    people = config.get('people') or {}
    for s in stages:
        for role, placeholder in ROLES.items():
            if people.get(role) and s.get('command'):s['command'] = s['command'].replace(placeholder, q(people[role]))
    nxt = next((s for s in stages if s['state'] in OPEN), None)
    from .delegation import effective
    _, digest, suspended, problem = effective(workspace)
    return {'workspace': str(workspace), 'stages': stages, 'next': nxt,
            'latest_run': latest.name if latest else None,
            'delegation': {'in_force': problem is None, 'problem': problem, 'policy_sha256': digest, 'suspended': sorted(suspended)},
            'notice': '完了はファイルがそろったことを表し、設計の承認ではない。人の判断待ちの手順はエージェントが代行しない。'
                      '委任方針で記録した判断はエージェント名と方針のハッシュを持ち、人の承認とは区別される。'}


def gates_stage(workspace, latest, q):
    if not (latest / 'gates.json').is_file():
        return stage('gates', 'TODO', f'{latest.name} のゲートを評価していない', f'aws-design gate run --workspace {q(workspace)} --run {latest.name}')
    from .gates import GATES_JA, load as load_gates
    report = load_gates(latest / 'gates.json')
    failing = [g for g in report.gates if g.status == 'FAIL']
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
    lines += ['', '次：' + (f"{n['stage']}（{n['state_ja']}）" + (f"\n\n    {n['command']}" if n.get('command') else '') +
                         (f"\n\n担当：{n['person']}" if n.get('person') else '') +
                         (f"\n\nエージェント：{n['agent']['name']} ×{n['agent']['count']}（" + '、'.join(f'{k}={v}' for k, v in n['agent']['handoff'].items() if k != 'runs') + '）'
                          + ''.join(f"\n- {i}：" + '、'.join(f'{k}={v}' for k, v in run.items()) for i, run in enumerate(n['agent']['handoff'].get('runs', []), 1))
                          if n.get('agent') else '') +
                         (f"\n\n委任されない理由：{'、'.join(n['delegation_refused'])}" if n.get('delegation_refused') else '') if n else 'なし'), '', report['notice']]
    return '\n'.join(lines) + '\n'


def run_scan(workspace, replace=False):
    from .source_set import dump, scan
    config = load(workspace)
    if not config.get('arp_root'):raise InputError('NO_ARP_ROOT')
    folder = Path(workspace) / 'sources';folder.mkdir(exist_ok=True)
    if replace:
        for name in ('proposal.json', 'set.json'):
            if (folder / name).is_file():(folder / name).replace(folder / f'{name}.previous')
    if (folder / 'proposal.json').exists():raise InputError('proposal already exists; approve it or run with --replace')
    proposal = scan(Path(config['arp_root']))
    (folder / 'proposal.json').write_bytes(dump(proposal.model_dump()))
    return {'proposal': str(folder / 'proposal.json'), 'undecided': [e.document_id for e in proposal.documents if e.status == 'UNDECIDED']}


def run_all(workspace, limit=16):
    """Perform every step that needs neither a person nor an agent's work: scans, generation, gates and
    the decisions an approved delegation policy covers. Stops at the first step that needs someone."""
    done = []
    for _ in range(limit):
        nxt = status(workspace)['next']
        if nxt is None:break
        if nxt['stage'] == 'sources' and nxt['state'] in ('TODO', 'STALE'):
            result = run_scan(workspace, replace=nxt['state'] == 'STALE');done.append({'step': 'scan', 'undecided': result['undecided']})
        elif nxt['state'] == 'DELEGATED':done.append(delegated(workspace, nxt))
        elif nxt['stage'] == 'generate' and nxt.get('command'):
            code, output, result = run_generate(workspace)
            done.append({'step': 'generate', 'run': output.name, 'exit_code': code, 'generation_status': result.get('generation_status'),
                         'gates': result.get('gates')})
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

    def role_args(p):
        p.add_argument('--approver', help='source-set approver the user names');p.add_argument('--architect', help='system-overview agreer the user names')
        p.add_argument('--adopter', help='policy-pack adopter the user names');p.add_argument('--reviewer', help='review-pack reviewer the user names')
    role_args(p)
    p = sub.add_parser('people', help='register the people the user names for each role');p.add_argument('--workspace', required=True);role_args(p)
    p = sub.add_parser('inbox', help='one workbook with every decision the workspace waits for');p.add_argument('--workspace', required=True)
    p.add_argument('--output', required=True, help='fresh folder')
    p = sub.add_parser('decide', help='record the decisions written in an inbox workbook, by the people named there or registered')
    p.add_argument('--workspace', required=True);p.add_argument('--workbook', required=True)
    p = sub.add_parser('status', help='each stage and the next step');p.add_argument('--workspace', required=True)
    p.add_argument('--markdown', action='store_true')
    p = sub.add_parser('run', help='perform steps that need no person: scan, generate, or all until a person is needed')
    p.add_argument('step', choices=['scan', 'generate', 'all'])
    p.add_argument('--workspace', required=True);p.add_argument('--replace', action='store_true', help='scan again, keeping the old files as *.previous')
    args = parser.parse_args(argv)
    try:
        workspace = Path(args.workspace)
        if args.command == 'init':
            if (workspace / CONFIG).exists():raise InputError('flow.json already exists')
            workspace.mkdir(parents=True, exist_ok=True)
            if any(is_agent(getattr(args, r)) for r in ROLES if getattr(args, r)):raise InputError('PERSON_IS_AGENT: register persons only')
            config = {'environment': args.environment, 'input': args.input, 'arp_root': args.arp_root, 'policy_pack': args.policy_pack,
                      'policy_input': 'input/design-with-policies.json' if args.policy_pack else None,
                      'source_trace': args.source_trace, 'evaluate': args.evaluate,
                      'overview': 'input/system-overview.json' if args.overview else None, 'asks': args.asks, 'library': args.library,
                      'people': {r: getattr(args, r).strip() for r in ROLES if getattr(args, r) and getattr(args, r).strip()} or None}
            (workspace / CONFIG).write_text(json.dumps({k: v for k, v in config.items() if v not in (None, False)}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            print(json.dumps({'workspace': str(workspace), 'next': status(workspace)['next']}, ensure_ascii=False));return 0
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
            print(json.dumps({'done': done, 'next': status(workspace)['next']}, ensure_ascii=False))
            return 2 if done and done[-1].get('exit_code') == 2 else 0
        if args.step == 'scan':
            print(json.dumps(run_scan(workspace, args.replace), ensure_ascii=False));return 0
        code, output, result = run_generate(workspace)
        brief = {k: result[k] for k in ('generation_status', 'errors', 'review_pack', 'source_set_status', 'input_completeness', 'gates') if k in result}
        print(json.dumps({'run': str(output), 'exit_code': code, **brief, 'next': status(workspace)['next']}, ensure_ascii=False));return code
    except (InputError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc) if isinstance(exc, InputError) else type(exc).__name__}, ensure_ascii=False));return 2


if __name__ == '__main__':
    raise SystemExit(main())
