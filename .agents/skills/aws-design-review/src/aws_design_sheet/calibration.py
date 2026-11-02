"""Calibration: a person audits a sample of agent decisions, and measured results narrow the delegation.

`audit_sample` picks the policy's share of agent decisions not yet audited into a workbook;
a person marks each CORRECT or WRONG and `audit_record` stores one record per row, bound to the
decision's target hash. `calibrate` counts per rule the decisions, audits and errors, the
review packets voided by missed canaries and the golden reports, and suspends a rule whose
error rate exceeds the policy's limit (once enough audits exist), whose golden cases fail, or
whose last packets mostly missed canaries. It recomputes from the evidence every time; it can
only narrow what the approved policy allows, never widen it.
"""
import json
import math
import random
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .delegation import RULES, Calibration, InputError, Suspension, decisions, effective, folder, now_stamp, person_name

HEADERS = ['ID', '規則', '判断', '対象', '判断日時', '判断者', '根拠', '判定(CORRECT/WRONG)', '理由', 'target_sha256']


class AuditRecord(BaseModel):
    model_config = ConfigDict(extra='forbid')
    contract: Literal['audit-record/1']
    decision_id: str
    rule: Literal[RULES]
    target_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    verdict: Literal['CORRECT', 'WRONG']
    reason: str = ''
    auditor: str = Field(min_length=1)
    audited_at: str


def audits(workspace):
    base = folder(workspace) / 'audits'
    return [AuditRecord.model_validate_json(p.read_bytes()) for p in sorted(base.glob('*.json'))] if base.is_dir() else []


def audit_sample(workspace, output, *, seed=0):
    policy, _, _, problem = effective(workspace)
    if problem:raise InputError(f'POLICY_NOT_IN_FORCE: {problem}')
    if Path(output).exists():raise InputError('output already exists; use a fresh folder')
    made = decisions(workspace)
    done = {a.decision_id for a in audits(workspace)}
    wanted = max(0, math.ceil(policy.audit.sample_rate * len(made)) - len(done))
    pending = [d for d in made if d.id not in done]
    if pending and not done and wanted == 0:wanted = 1
    chosen = sorted(random.Random(seed).sample(pending, min(wanted, len(pending))), key=lambda d: d.id)
    from openpyxl import Workbook
    from openpyxl.worksheet.datavalidation import DataValidation
    book = Workbook();sheet = book.active;sheet.title = '監査';sheet.append(HEADERS)
    for d in chosen:
        sheet.append([d.id, d.rule, d.summary, d.target, d.decided_at, d.decided_by, '；'.join(d.basis.evidence)[:500], '', '', d.target_sha256])
    check = DataValidation(type='list', formula1='"CORRECT,WRONG"', allow_blank=True);sheet.add_data_validation(check);check.add(f'H2:H{max(2, sheet.max_row)}')
    Path(output).mkdir(parents=True)
    book.save(Path(output) / 'audit.xlsx')
    return {'audit': str(Path(output) / 'audit.xlsx'), 'sampled': len(chosen), 'decisions': len(made), 'already_audited': len(done)}


def audit_record(workspace, workbook, auditor, *, now=None):
    """One AuditRecord per filled row; the decision must exist and its target must be unchanged."""
    auditor = person_name(auditor, 'AUDITOR')
    from openpyxl import load_workbook
    rows = list(load_workbook(workbook, read_only=True)['監査'].iter_rows(values_only=True))
    if not rows or list(rows[0][:len(HEADERS)]) != HEADERS:raise InputError('NOT_AN_AUDIT_WORKBOOK')
    made = {d.id: d for d in decisions(workspace)}
    base = folder(workspace) / 'audits';base.mkdir(parents=True, exist_ok=True)
    written, errors = [], []
    for row in rows[1:]:
        decision_id, verdict = row[0], str(row[7] or '').strip().upper()
        if not verdict:continue
        d = made.get(decision_id)
        if d is None:errors.append(f'{decision_id}: UNKNOWN_DECISION');continue
        if verdict not in ('CORRECT', 'WRONG'):errors.append(f'{decision_id}: INVALID_VERDICT');continue
        if row[9] != d.target_sha256:errors.append(f'{decision_id}: TARGET_CHANGED');continue
        written.append(AuditRecord(contract='audit-record/1', decision_id=d.id, rule=d.rule, target_sha256=d.target_sha256, verdict=verdict,
                                   reason=str(row[8] or ''), auditor=auditor, audited_at=now_stamp(now)))
    if errors:raise InputError('REFUSED: ' + '；'.join(errors))
    for record in written:(base / f'{record.decision_id}.json').write_text(json.dumps(record.model_dump(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {'recorded': len(written), 'wrong': sum(r.verdict == 'WRONG' for r in written)}


def canary_history(workspace):
    from .review_agents import Escalation
    found = []
    for path in sorted(Path(workspace).glob('runs/*/agent-review/escalation.json')):found.append(Escalation.model_validate_json(path.read_bytes()).status)
    return found


def calibrate(workspace, golden_paths=(), *, now=None):
    policy, digest, _, problem = effective(workspace, calibrated=False)
    if problem:raise InputError(f'POLICY_NOT_IN_FORCE: {problem}')
    from .golden import GoldenReport
    goldens = [GoldenReport.model_validate_json(Path(p).read_bytes()) for p in golden_paths]
    made, checked = decisions(workspace), audits(workspace)
    history = canary_history(workspace)
    rules, suspended = {}, []
    for name in RULES:
        audited = [a for a in checked if a.rule == name]
        wrong = sum(a.verdict == 'WRONG' for a in audited)
        rate = wrong / len(audited) if audited else None
        golden = [g.rules[name] for g in goldens if name in g.rules]
        row = {'decisions': sum(d.rule == name for d in made), 'audited': len(audited), 'wrong': wrong,
               'error_rate': round(rate, 4) if rate is not None else None, 'golden': golden}
        reasons = []
        if rate is not None and len(audited) >= policy.audit.min_audits and rate > policy.audit.max_error_rate:
            reasons.append(f'監査の誤り率 {rate:.1%}（{wrong}/{len(audited)}）が上限 {policy.audit.max_error_rate:.1%} を超えた')
        if 'FAIL' in golden:reasons.append('正解集の判定が不合格')
        if name == 'review':
            recent = history[-3:]
            row['canary_missed_recent'] = recent.count('CANARY_MISSED')
            if recent.count('CANARY_MISSED') >= 2:reasons.append(f'直近 {len(recent)} 回のパケットのうち {recent.count("CANARY_MISSED")} 回で検出用の行を見逃した')
        if reasons:suspended.append(Suspension(rule=name, reason='；'.join(reasons), since=now_stamp(now)))
        row['suspended'] = bool(reasons)
        rules[name] = row
    record = Calibration(contract='delegation-calibration/1', policy_sha256=digest, suspended=suspended)
    (folder(workspace) / 'calibration.json').write_text(json.dumps(record.model_dump(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {'policy_sha256': digest, 'rules': rules, 'suspended': [s.rule for s in suspended],
            'notice': '停止は委任の範囲を狭めるだけで、広げるには人が委任方針を承認し直す。'}
