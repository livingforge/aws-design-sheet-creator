"""Agent review of P2 rows: a packet with planted canaries, independent verdicts, and agreement.

`packet` takes the rows of a review pack that a delegation policy lets agents judge, hides
their item IDs behind opaque keys and mixes in canary rows: copies of real rows whose value
was changed so that it contradicts the row's own evidence. The key that tells canaries from
real rows stays in delegation/keys, which agents are not given. Each reviewer agent writes
an `agent-verdicts` file. `agree` voids every reviewer who passed a canary or skipped a row,
records OK only for rows every remaining reviewer passed (at least the number the policy
asks), and escalates everything else to a person with the reasons. Agents never record NG:
a row an agent doubts goes to a person.
"""
import hashlib
import json
import random
import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from .delegation import Basis, agent, now_stamp

Hash = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Key = Annotated[str, Field(pattern=r'^r[0-9a-f]{12}$')]
INSTRUCTIONS = ('各行の値が、出典（evidence_at・documents）の CURRENT 文書の記載と一致するかを確かめる。一致すれば OK、'
                '一致しない・出典で確かめられない・迷う場合は NG とし、reason に確かめた箇所と理由を書く。行の順序や見た目から推測しない。')


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


class PacketRow(Strict):
    key: Key
    resource_id: str
    resource_type: str | None = None
    property: str
    value: str
    tier: str | None = None
    documents: list[str] = Field(default_factory=list)
    evidence_at: str = ''
    evidence: str = ''


class Packet(Strict):
    contract: Literal['review-packet/1']
    run: str
    pack_sha256: Hash
    key_sha256: Hash
    instructions: str
    rows: list[PacketRow]


class AgentVerdict(Strict):
    key: Key
    verdict: Literal['OK', 'NG']
    reason: str = Field(min_length=1)
    checked: list[str] = Field(default_factory=list)


class AgentVerdicts(Strict):
    contract: Literal['agent-verdicts/1']
    packet_sha256: Hash
    actor: str = Field(min_length=1)
    model: str = ''
    verdicts: list[AgentVerdict]


class CanaryKeyRow(Strict):
    canary: bool
    item_id: str | None = None
    fingerprint: str | None = None
    planted_from: str | None = None


class CanaryKey(Strict):
    contract: Literal['canary-key/1']
    run: str
    rows: dict[str, CanaryKeyRow]


class Reviewer(Strict):
    actor: str
    model: str = ''
    canaries_total: int
    canaries_caught: int
    missing_rows: int
    void: bool
    why: str = ''


class Escalated(Strict):
    item_id: str
    fingerprint: str
    why: str


class Escalation(Strict):
    contract: Literal['agent-escalation/1']
    run: str
    packet_sha256: Hash
    status: Literal['AGREED', 'CANARY_MISSED', 'INSUFFICIENT_REVIEWERS']
    reviewers: list[Reviewer]
    agreed_ok: list[str] = Field(default_factory=list)
    escalated: list[Escalated] = Field(default_factory=list)


class InputError(ValueError):
    pass


def sha(raw):return hashlib.sha256(raw).hexdigest()


def dump(value):return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def mutate(value, others, rng):
    """A different value that contradicts the original: a changed number, a flipped boolean word, or another row's value."""
    if value in ('true', 'false'):return 'false' if value == 'true' else 'true'
    digits = list(re.finditer(r'\d+', value))
    if digits:
        m = digits[rng.randrange(len(digits))]
        number = int(m.group(0))
        changed = str(number + rng.choice((1, 2, 3, 7)) if number < 250 or '.' not in value else max(0, number - rng.choice((1, 2, 3))))
        return value[:m.start()] + changed + value[m.end():]
    pool = [o for o in others if o and o != value]
    return rng.choice(pool) if pool else value + '-x'


def escalated_before(workspace):
    """(item_id, fingerprint) pairs agents already escalated in earlier packets; they are not sent to agents again."""
    seen = set()
    for path in Path(workspace).glob('runs/*/agent-review/escalation.json'):
        found = Escalation.model_validate_json(path.read_bytes())
        seen |= {(e.item_id, e.fingerprint) for e in found.escalated}
    return seen


def delegable(pack, priorities, skip=()):
    return [r for r in pack['rows'] if r['priority'] in priorities and r.get('fingerprint') and (r['item_id'], r['fingerprint']) not in skip]


def packet(pack, pack_raw, run, rows, canaries, *, seed=None):
    """(packet, key) for the given pack rows with `canaries` planted rows."""
    if not rows:raise InputError('NO_ROWS_TO_DELEGATE')
    rng = random.Random(seed if seed is not None else sha(pack_raw))
    key_rows, out = {}, []

    def new_key():
        while True:
            k = 'r' + '%012x' % rng.getrandbits(48)
            if k not in key_rows:return k
    for r in rows:
        k = new_key();key_rows[k] = CanaryKeyRow(canary=False, item_id=r['item_id'], fingerprint=r['fingerprint'])
        out.append(PacketRow(key=k, resource_id=str(r['resource_id']), resource_type=r.get('resource_type'), property=r['property'], value=r['value'] or '',
                             tier=r.get('tier'), documents=r.get('documents', []), evidence_at=r.get('evidence_at') or '', evidence=r.get('evidence') or ''))
    # Canaries copy rows that carry evidence and a value, so a reviewer who reads the source can tell;
    # rows outside the packet first, so a canary does not sit beside its own original.
    sent = {r['item_id'] for r in rows}
    evidenced = [r for r in pack['rows'] if r.get('value') and (r.get('evidence') or r.get('evidence_at'))]
    sources = [r for r in evidenced if r['item_id'] not in sent] or evidenced or [r for r in rows if r.get('value')] or rows
    values = sorted({r['value'] for r in pack['rows'] if r.get('value')})
    for _ in range(canaries):
        base = rng.choice(sources)
        changed = mutate(base['value'] or '', values, rng)
        k = new_key();key_rows[k] = CanaryKeyRow(canary=True, planted_from=base['item_id'])
        out.append(PacketRow(key=k, resource_id=str(base['resource_id']), resource_type=base.get('resource_type'), property=base['property'], value=changed,
                             tier=base.get('tier'), documents=base.get('documents', []), evidence_at=base.get('evidence_at') or '', evidence=base.get('evidence') or ''))
    rng.shuffle(out)
    key = CanaryKey(contract='canary-key/1', run=run, rows=key_rows)
    key_raw = dump(key.model_dump())
    made = Packet(contract='review-packet/1', run=run, pack_sha256=sha(pack_raw), key_sha256=sha(key_raw), instructions=INSTRUCTIONS, rows=out)
    return made, key_raw


def agree(packet_raw, key_raw, verdict_raws, rule, policy_sha256, *, now=None):
    """(decisions, escalation) from independent verdict files under the review rule of a delegation policy."""
    found = Packet.model_validate_json(packet_raw)
    if sha(key_raw) != found.key_sha256:raise InputError('KEY_MISMATCH: the canary key is not the one made with this packet')
    key = CanaryKey.model_validate_json(key_raw)
    packet_sha = sha(packet_raw)
    files = [AgentVerdicts.model_validate_json(raw) for raw in verdict_raws]
    actors = [agent(f.actor) for f in files]
    if len(set(actors)) != len(actors):raise InputError('SAME_ACTOR: verdict files must come from different actors')
    reviewers, valid = [], []
    canary_keys = {k for k, v in key.rows.items() if v.canary}
    real_keys = [k for k, v in key.rows.items() if not v.canary]
    for f, name in zip(files, actors):
        by_key = {v.key: v for v in f.verdicts}
        missing = [k for k in key.rows if k not in by_key]
        caught = sum(by_key[k].verdict == 'NG' for k in canary_keys if k in by_key)
        why = ('PACKET_MISMATCH' if f.packet_sha256 != packet_sha else 'ROWS_MISSING' if missing else
               'CANARY_PASSED' if caught < len(canary_keys) else '')
        reviewers.append(Reviewer(actor=name, model=f.model, canaries_total=len(canary_keys), canaries_caught=caught, missing_rows=len(missing),
                                  void=bool(why), why=why))
        if not why:valid.append((name, f, by_key))
    if rule.require_distinct_models:
        models = [f.model.strip().lower() for _, f, _ in valid]
        if '' in models or len(set(models)) != len(models):
            valid = []
            for r in reviewers:
                if not r.void:r.void, r.why = True, 'MODELS_NOT_DISTINCT'
    if len(valid) < rule.reviewers:
        status = 'CANARY_MISSED' if any(r.why == 'CANARY_PASSED' for r in reviewers) else 'INSUFFICIENT_REVIEWERS'
        escalated = [Escalated(item_id=key.rows[k].item_id, fingerprint=key.rows[k].fingerprint, why=status) for k in real_keys]
        return None, Escalation(contract='agent-escalation/1', run=found.run, packet_sha256=packet_sha, status=status, reviewers=reviewers, escalated=escalated)
    stamp = now_stamp(now)
    names = [n for n, _, _ in valid]
    basis = Basis(policy_sha256=policy_sha256, rule='review', actors=names,
                  evidence=[f'packet sha256 {packet_sha}'] + [f'verdicts {n} sha256 {sha(raw)}' for n, raw in zip(actors, verdict_raws)])
    decisions, agreed, escalated = [], [], []
    for k in real_keys:
        row = key.rows[k]
        verdicts = [(n, by_key[k]) for n, _, by_key in valid]
        if all(v.verdict == 'OK' for _, v in verdicts):
            decisions.append({'item_id': row.item_id, 'fingerprint': row.fingerprint, 'verdict': 'OK', 'reviewer': '+'.join(names), 'recorded_at': stamp,
                              'comment': ' / '.join(f'{n}: {v.reason}' for n, v in verdicts)[:1000], 'delegation': basis.model_dump()})
            agreed.append(row.item_id)
        else:
            doubts = '；'.join(f'{n} NG：{v.reason}' for n, v in verdicts if v.verdict == 'NG')
            escalated.append(Escalated(item_id=row.item_id, fingerprint=row.fingerprint, why=doubts[:1000]))
    return ({'version': '1', 'decisions': decisions},
            Escalation(contract='agent-escalation/1', run=found.run, packet_sha256=packet_sha, status='AGREED', reviewers=reviewers,
                       agreed_ok=agreed, escalated=escalated))
