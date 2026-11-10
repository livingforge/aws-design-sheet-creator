"""Delegation policy: the decisions a person lets agents take, approved once and bound by its hash.

A person the user names approves a policy file. Within its rules, `aws-design flow run all`
records decisions itself under an `agent:` name, with the policy hash, the rule, the agent
outputs it rests on and the evidence; anything outside the rules, a failing gate or a
suspended rule stays a decision for a person. No rule covers P1 review rows, workbook
changes or promotion to the organisation library, and an agent never signs as a person:
commands that record a person's decision refuse `agent:` names.
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

AGENT_PREFIX = 'agent:'
FLOW_AGENT = 'agent:aws-design flow'
# The name a draft records what it settled under; never a person's approval nor a delegated decision.
DRAFT_AGENT = 'agent:aws-design flow draft'
RULES = ('source_set', 'overview', 'policy_pack', 'review', 'external_mapping')
RULES_JA = {'source_set': '根拠文書セットの承認', 'overview': 'システム概要の合意', 'policy_pack': '方針パックの採用',
            'review': 'レビュー判定（P2）', 'external_mapping': '外部シートの対応付け辞書の承認'}
ALWAYS_PERSON = ['P1のレビュー判定', '設計書の変更の適用（aws-design changes apply）', '組織ライブラリへの昇格', '委任方針そのものの承認']
SOURCE_REASONS = ('ONLY_VERSION', 'NEWEST_VERSION', 'OLDER_VERSION', 'DUPLICATE_OF')
Hash = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]


class InputError(ValueError):
    pass


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


def is_agent(name):return str(name or '').strip().lower().startswith(AGENT_PREFIX)


def agent(name):
    """An agent actor as recorded: `agent:` and the actor name the parent gave it."""
    name = str(name or '').strip()
    if not name:raise InputError('ACTOR_REQUIRED')
    return name if is_agent(name) else AGENT_PREFIX + name


def person_name(name, role='APPROVER'):
    """A person's name for a command that records a person's decision; agent names are refused."""
    name = str(name or '').strip()
    if not name:raise InputError(f'{role}_REQUIRED')
    if is_agent(name):raise InputError(f'{role}_IS_AGENT: agent decisions are recorded only by aws-design flow under an approved delegation policy')
    return name


def now_stamp(now=None):return (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


class Basis(Strict):
    """Why an agent could record a decision: the approved policy, the rule and what it rests on."""
    policy_sha256: Hash
    rule: Literal[RULES]
    actors: list[str] = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)


class SourceSetRule(Strict):
    enabled: bool = True
    # Proposal reasons accepted as proposed; UNDECIDED documents and archive folders always go to a person.
    accept_reasons: list[Literal[SOURCE_REASONS]] = Field(default_factory=lambda: list(SOURCE_REASONS))


class OverviewRule(Strict):
    enabled: bool = True
    # Two independent drafts must agree (aws-design system compare) besides the independent review.
    require_second_draft: bool = True
    require_distinct_models: bool = False
    # Finding categories that do not stop agent agreement; CONFLICT always does.
    allow_findings: list[Literal['GAP', 'OPEN']] = Field(default_factory=list)


class PolicyPackRule(Strict):
    enabled: bool = True
    # Pack IDs agents may adopt, each optionally pinned to its canonical sha256.
    packs: dict[str, Hash | None] = Field(default_factory=dict)


class ReviewRule(Strict):
    enabled: bool = True
    priorities: list[Literal['P2']] = Field(default_factory=lambda: ['P2'])
    reviewers: int = Field(default=2, ge=2, le=5)
    require_distinct_models: bool = False
    # Planted rows with a value that contradicts their evidence; a reviewer who passes one is void for the packet.
    canaries: int = Field(default=3, ge=1, le=50)


class ExternalMappingRule(Strict):
    enabled: bool = True
    require_distinct_models: bool = False


class Audit(Strict):
    sample_rate: float = Field(default=0.1, ge=0, le=1)
    max_error_rate: float = Field(default=0.05, ge=0, le=1)
    min_audits: int = Field(default=10, ge=1)


class Rules(Strict):
    source_set: SourceSetRule | None = None
    overview: OverviewRule | None = None
    policy_pack: PolicyPackRule | None = None
    review: ReviewRule | None = None
    external_mapping: ExternalMappingRule | None = None


class Policy(Strict):
    contract: Literal['delegation-policy/1']
    id: str = Field(pattern=r'^[a-z][a-z0-9-]{0,63}$')
    description: str = ''
    rules: Rules
    audit: Audit = Field(default_factory=Audit)


class PolicyApproval(Strict):
    contract: Literal['delegation-approval/1']
    policy_sha256: Hash
    approver: str = Field(min_length=1)
    approved_at: str


class AutoDecision(Strict):
    """One decision an agent recorded under the policy; the audit samples these."""
    contract: Literal['auto-decision/1']
    id: str = Field(pattern=r'^[0-9]{4}-[a-z_]+$')
    rule: Literal[RULES]
    decided_by: str = Field(pattern=r'^agent:.+')
    decided_at: str
    basis: Basis
    target: str
    target_sha256: Hash
    summary: str


class Suspension(Strict):
    rule: Literal[RULES]
    reason: str = Field(min_length=1)
    since: str


class Calibration(Strict):
    """Rules suspended by measured results; suspension only narrows what the approved policy allows."""
    contract: Literal['delegation-calibration/1']
    policy_sha256: Hash
    suspended: list[Suspension] = Field(default_factory=list)


def canonical(policy):return hashlib.sha256(json.dumps(policy.model_dump(mode='json'), ensure_ascii=False, sort_keys=True).encode('utf-8')).hexdigest()


def preset(name='standard'):
    """A policy draft for a person to read and approve; `strict` delegates only mechanical steps."""
    if name == 'strict':
        rules = Rules(source_set=SourceSetRule(accept_reasons=['ONLY_VERSION', 'DUPLICATE_OF']), review=ReviewRule(reviewers=3, require_distinct_models=True, canaries=5))
    else:
        rules = Rules(source_set=SourceSetRule(), overview=OverviewRule(), policy_pack=PolicyPackRule(packs={'aws-security-baseline': None}),
                      review=ReviewRule(), external_mapping=ExternalMappingRule())
    return Policy(contract='delegation-policy/1', id=f'{name}-delegation', description='', rules=rules)


def load_policy(raw):
    import yaml
    return Policy.model_validate(yaml.safe_load(raw))


def approve(raw, approver, *, now=None):
    policy = load_policy(raw)
    return PolicyApproval(contract='delegation-approval/1', policy_sha256=canonical(policy), approver=person_name(approver), approved_at=now_stamp(now))


def folder(workspace):return Path(workspace) / 'delegation'


def effective(workspace, calibrated=True):
    """(policy, sha256, suspended rules, problem): the workspace policy if a person approved it in its current form.

    `calibrated=False` ignores the current suspensions, for calibrate to compute them afresh."""
    base = folder(workspace)
    path, record = base / 'policy.json', base / 'approval.json'
    if not path.is_file():return None, None, set(), 'NO_POLICY'
    try:policy = load_policy(path.read_bytes())
    except (ValidationError, ValueError) as exc:return None, None, set(), f'POLICY_INVALID: {str(exc)[:200]}'
    digest = canonical(policy)
    if not record.is_file():return None, digest, set(), 'POLICY_NOT_APPROVED'
    try:approval = PolicyApproval.model_validate_json(record.read_bytes())
    except (ValidationError, ValueError):return None, digest, set(), 'APPROVAL_INVALID'
    if approval.policy_sha256 != digest:return None, digest, set(), 'POLICY_CHANGED_AFTER_APPROVAL'
    if is_agent(approval.approver):return None, digest, set(), 'APPROVER_IS_AGENT'
    suspended = set()
    calibration = base / 'calibration.json'
    if calibrated and calibration.is_file():
        try:
            found = Calibration.model_validate_json(calibration.read_bytes())
            if found.policy_sha256 == digest:suspended = {s.rule for s in found.suspended}
        except (ValidationError, ValueError):return None, digest, set(), 'CALIBRATION_INVALID'
    return policy, digest, suspended, None


def rule(workspace, name):
    """(rule settings, policy sha256, why not) for one rule of the workspace policy."""
    policy, digest, suspended, problem = effective(workspace)
    if problem:return None, digest, problem
    settings = getattr(policy.rules, name)
    if settings is None or not settings.enabled:return None, digest, 'RULE_NOT_DELEGATED'
    if name in suspended:return None, digest, 'RULE_SUSPENDED'
    return settings, digest, None


def log(workspace, rule_name, decided_by, basis, target, summary, *, now=None):
    """Append one AutoDecision record to delegation/log and return it."""
    base = folder(workspace) / 'log';base.mkdir(parents=True, exist_ok=True)
    number = 1 + max((int(p.name[:4]) for p in base.glob('[0-9][0-9][0-9][0-9]-*.json')), default=0)
    target = Path(target)
    record = AutoDecision(contract='auto-decision/1', id=f'{number:04d}-{rule_name}', rule=rule_name, decided_by=decided_by, decided_at=now_stamp(now),
                          basis=basis, target=target.relative_to(workspace).as_posix() if target.is_relative_to(workspace) else str(target),
                          target_sha256=hashlib.sha256(target.read_bytes()).hexdigest(), summary=summary)
    (base / f'{record.id}.json').write_text(json.dumps(record.model_dump(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return record


def decisions(workspace):
    base = folder(workspace) / 'log'
    return [AutoDecision.model_validate_json(p.read_bytes()) for p in sorted(base.glob('[0-9][0-9][0-9][0-9]-*.json'))] if base.is_dir() else []


def markdown(policy, digest=None):
    """For the person who approves: what agents may decide, on what condition, and what always stays with people."""
    r = policy.rules
    lines = [f'# 委任方針 {policy.id}', '', policy.description or '', '', '| 判断 | エージェントに任せる条件 |', '|---|---|']
    describe = {
        'source_set': lambda s: '提案の理由が ' + '・'.join(s.accept_reasons) + ' だけで、UNDECIDED と原本の問題がない',
        'overview': lambda s: '独立レビューが受理' + ('、別の作成担当の下書きと compare が一致' if s.require_second_draft else '')
                              + ('、作成担当のモデルが異なる' if s.require_distinct_models else '') + '、矛盾なし'
                              + ('' if set(s.allow_findings) >= {'GAP', 'OPEN'} else '、' + '・'.join(x for x in ('GAP', 'OPEN') if x not in s.allow_findings) + ' の指摘なし'),
        'policy_pack': lambda s: '方針パック ' + ('、'.join(f'{k}' + (f'（sha256 {v[:12]}）' if v else '') for k, v in s.packs.items()) or 'なし'),
        'review': lambda s: f"P2 の行を {s.reviewers} 体の独立レビュー担当がすべて OK とし、仕込んだ検出用の行 {s.canaries} 件をすべて NG とした"
                            + ('、モデルが互いに異なる' if s.require_distinct_models else ''),
        'external_mapping': lambda s: '2つの独立した読み取りが同じセルで一致し、独立レビューが受理' + ('、モデルが異なる' if s.require_distinct_models else ''),
    }
    for name in RULES:
        settings = getattr(r, name)
        lines.append(f"| {RULES_JA[name]} | {describe[name](settings) if settings is not None and settings.enabled else '任せない（人が判断）'} |")
    lines += ['', '常に人が判断：' + '、'.join(ALWAYS_PERSON) + '。', '',
              f"事後監査：エージェントの判断の {policy.audit.sample_rate:.0%} を抜き取り、誤り率が {policy.audit.max_error_rate:.0%} を超えた規則は"
              f"（監査 {policy.audit.min_audits} 件以上で）停止する。"]
    if digest:lines += ['', f'sha256 {digest}']
    return '\n'.join(lines) + '\n'


def write_new(path, data):
    path = Path(path)
    if path.exists():raise InputError('output already exists; use a fresh path')
    path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(data)


def dump(value):return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design delegation', description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('init', help='write a policy draft for a person to read and approve');p.add_argument('--preset', choices=['standard', 'strict'], default='standard')
    p.add_argument('--output', required=True)
    p = sub.add_parser('show', help='Markdown summary of a policy for its approver');p.add_argument('policy')
    p = sub.add_parser('approve', help='record approval of a policy by a person the user names');p.add_argument('policy')
    p.add_argument('--approver', required=True);p.add_argument('--output', required=True)
    p = sub.add_parser('status', help='whether a workspace policy is in force, rule by rule');p.add_argument('--workspace', required=True)
    p = sub.add_parser('audit', help='sample agent decisions for a person to check, or record that check')
    p.add_argument('action', choices=['sample', 'record']);p.add_argument('--workspace', required=True)
    p.add_argument('--output', help='sample: fresh folder');p.add_argument('--seed', type=int, default=0)
    p.add_argument('--workbook', help='record: the filled audit workbook');p.add_argument('--auditor', help='record: the person who checked')
    p = sub.add_parser('calibrate', help='suspend rules whose measured error, canary or golden results fall short');p.add_argument('--workspace', required=True)
    p.add_argument('--golden', action='append', default=[], help='aws-design golden report to take into account')
    args = parser.parse_args(argv)
    try:
        if args.command == 'init':
            write_new(args.output, dump(preset(args.preset).model_dump(mode='json')))
            print(json.dumps({'policy': args.output, 'next': 'aws-design delegation show で内容を示し、利用者が指名した人が approve する'}, ensure_ascii=False));return 0
        if args.command == 'show':
            policy = load_policy(Path(args.policy).read_bytes())
            sys.stdout.buffer.write(markdown(policy, canonical(policy)).encode('utf-8'));return 0
        if args.command == 'approve':
            record = approve(Path(args.policy).read_bytes(), args.approver)
            write_new(args.output, dump(record.model_dump()))
            print(json.dumps({'approval': args.output, 'policy_sha256': record.policy_sha256, 'approver': record.approver}, ensure_ascii=False));return 0
        if args.command == 'status':
            policy, digest, suspended, problem = effective(args.workspace)
            rules = {}
            for name in RULES:
                settings, _, why = rule(args.workspace, name)
                rules[name] = 'DELEGATED' if settings is not None else why
            print(json.dumps({'in_force': problem is None, 'problem': problem, 'policy_sha256': digest, 'rules': rules,
                              'decisions': len(decisions(args.workspace))}, ensure_ascii=False, indent=2));return 0
        from .calibration import audit_record, audit_sample, calibrate
        if args.command == 'audit':
            if args.action == 'sample':
                if not args.output:raise InputError('--output is required for sample')
                print(json.dumps(audit_sample(Path(args.workspace), Path(args.output), seed=args.seed), ensure_ascii=False));return 0
            if not args.workbook or not args.auditor:raise InputError('--workbook and --auditor are required for record')
            print(json.dumps(audit_record(Path(args.workspace), Path(args.workbook), args.auditor), ensure_ascii=False));return 0
        report = calibrate(Path(args.workspace), [Path(g) for g in args.golden])
        print(json.dumps(report, ensure_ascii=False, indent=2));return 0
    except ValidationError as exc:
        errors = [{'loc': [str(x) for x in e['loc']], 'type': e['type']} for e in exc.errors(include_input=False, include_context=False)]
        print(json.dumps({'status': 'ERROR', 'message': 'CONTRACT_INVALID', 'errors': errors}, ensure_ascii=False));return 2
    except (InputError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc) if isinstance(exc, InputError) else type(exc).__name__}, ensure_ascii=False));return 2


if __name__ == '__main__':
    raise SystemExit(main())
