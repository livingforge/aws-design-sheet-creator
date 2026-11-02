"""Autopilot: the decisions `aws-design flow run all` records itself under an approved delegation policy.

Each `plan_*` reads the workspace and returns either the delegation that applies (rule and
policy hash) or the reasons it does not; `aws-design flow status` shows them, so a person sees
why a step waits for them. Each `do_*` records the decision under `agent:aws-design flow`
with a delegation basis and appends an AutoDecision to delegation/log. Nothing here runs when
the policy is missing, unapproved, changed since approval or suspended for the rule.
"""
import hashlib
import json
from pathlib import Path

from .delegation import FLOW_AGENT, Basis, agent, log, rule

SECOND_DRAFT = 'input/system-overview-second.json'


def sha(raw):return hashlib.sha256(raw).hexdigest()


def keys_folder(workspace):return Path(workspace) / 'delegation' / 'keys'


# Source set ------------------------------------------------------------------------------------

def plan_sources(workspace, config):
    settings, digest, why = rule(workspace, 'source_set')
    if why:return None, [why]
    from .contracts import validate
    from .source_set import SourceSet, blocking
    proposal_path = Path(workspace) / 'sources' / 'proposal.json'
    checked = validate(proposal_path, 'source-set')
    if checked['status'] == 'FAIL':return None, ['PROPOSAL_CONTRACT_INVALID']
    proposal = SourceSet.model_validate_json(proposal_path.read_bytes())
    reasons = []
    for e in proposal.documents:
        if e.status == 'UNDECIDED':reasons.append(f'UNDECIDED {e.document_id}（{e.reason}）')
        elif e.reason not in settings.accept_reasons:reasons.append(f'REASON_NOT_DELEGATED {e.document_id}（{e.reason}）')
    errors, _ = blocking(proposal.issues, {e.document_id: e.status for e in proposal.documents})
    reasons += [f"SOURCE_ISSUE {i['code']} {i['document']}" for i in errors]
    return (None, reasons) if reasons else ({'rule': 'source_set', 'policy_sha256': digest}, [])


def do_sources(workspace, config, plan):
    from .source_set import approve, dump
    workspace = Path(workspace)
    raw = (workspace / 'sources' / 'proposal.json').read_bytes()
    basis = Basis(policy_sha256=plan['policy_sha256'], rule='source_set', actors=[FLOW_AGENT], evidence=[f'proposal sha256 {sha(raw)}'])
    approved = approve(Path(config['arp_root']), raw, FLOW_AGENT, {}, delegation=basis)
    target = workspace / 'sources' / 'set.json'
    target.write_bytes(dump(approved.model_dump()))
    counts = {}
    for e in approved.documents:counts[e.status] = counts.get(e.status, 0) + 1
    record = log(workspace, 'source_set', FLOW_AGENT, basis, target, '提案どおり承認：' + '、'.join(f'{k} {v}' for k, v in sorted(counts.items())))
    return {'step': 'approve-sources', 'auto_decision': record.id}


# System overview -------------------------------------------------------------------------------

def overview_rule(workspace):
    settings, _, why = rule(workspace, 'overview')
    return None if why else settings


def plan_overview(workspace, config, path, review):
    """Agreement of an independently reviewed draft; `review` is the accepted review record."""
    settings, digest, why = rule(workspace, 'overview')
    if why:return None, [why]
    from .system_overview import check, compare, load
    raw = path.read_bytes()
    overview = load(raw)
    if overview.author is None:return None, ['NOT_DRAFTED_BY_AGENT']
    report = check(overview)
    reasons = []
    categories = {}
    for f in report['findings']:categories[f['category']] = categories.get(f['category'], 0) + 1
    for category, count in sorted(categories.items()):
        if category == 'CONFLICT' or category not in settings.allow_findings:reasons.append(f'FINDINGS {category} {count}')
    actors = [agent(overview.author.actor), agent(review['actor'])]
    models = [overview.author.model]
    evidence = [f'overview sha256 {sha(raw)}', f"review by {review['actor']}"]
    if settings.require_second_draft:
        second_path = Path(workspace) / SECOND_DRAFT
        if not second_path.is_file():reasons.append('SECOND_DRAFT_MISSING')
        else:
            second = load(second_path.read_bytes())
            try:compared = compare(overview, second)
            except ValueError as exc:compared = {'status': str(exc).split(':', 1)[0]}
            if compared['status'] != 'AGREE':reasons.append(f"DRAFTS_{compared['status']}")
            if second.author:actors.append(agent(second.author.actor));models.append(second.author.model)
            evidence.append(f'second draft sha256 {sha(second_path.read_bytes())}')
    if settings.require_distinct_models and (len(models) < 2 or '' in [m.strip() for m in models] or len({m.strip().lower() for m in models}) != len(models)):
        reasons.append('MODELS_NOT_DISTINCT')
    if reasons:return None, reasons
    return {'rule': 'overview', 'policy_sha256': digest, 'actors': actors, 'evidence': evidence}, []


def do_overview(workspace, config, plan, path, target):
    from .system_overview import approve
    basis = Basis(policy_sha256=plan['policy_sha256'], rule='overview', actors=plan['actors'], evidence=plan['evidence'])
    record = approve(path.read_bytes(), FLOW_AGENT, delegation=basis)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    found = log(workspace, 'overview', FLOW_AGENT, basis, target, f"概要に合意（判定 {record['assessment']}）")
    return {'step': 'agree-overview', 'auto_decision': found.id}


# Policy pack -----------------------------------------------------------------------------------

def plan_policy(workspace, config):
    settings, digest, why = rule(workspace, 'policy_pack')
    if why:return None, [why]
    from .policy_packs import InputError as PackError, load
    name = config['policy_pack']
    if name not in settings.packs:return None, [f'PACK_NOT_DELEGATED {name}']
    try:pack, pack_digest = load(name, config.get('library'))
    except (PackError, ValueError):return None, [f'PACK_UNREADABLE {name}']
    pinned = settings.packs[name]
    if pinned and pinned != pack_digest:return None, [f'PACK_CHANGED {name}']
    return {'rule': 'policy_pack', 'policy_sha256': digest, 'pack_sha256': pack_digest}, []


def do_policy(workspace, config, plan, source_input, policy_input):
    import yaml
    from .policy_packs import apply, load
    pack, digest = load(config['policy_pack'], config.get('library'))
    result, report = apply(yaml.safe_load(source_input.read_bytes()), pack, digest, adopted_by=FLOW_AGENT)
    policy_input.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    basis = Basis(policy_sha256=plan['policy_sha256'], rule='policy_pack', actors=[FLOW_AGENT],
                  evidence=[f"pack {pack.id}@{pack.version} sha256 {digest}", f'input sha256 {sha(source_input.read_bytes())}'])
    found = log(workspace, 'policy_pack', FLOW_AGENT, basis, policy_input, f"{pack.id} を採用（宣言 {len(report['added'])}件）")
    return {'step': 'adopt-policy-pack', 'auto_decision': found.id}


# Review ----------------------------------------------------------------------------------------

def plan_review(workspace, latest, pack):
    """What agent review the latest run still needs: None, or a dict with `action` packet, agents or agree."""
    settings, digest, why = rule(workspace, 'review')
    if why:return None, [why]
    from .review_agents import delegable, escalated_before
    folder = latest / 'agent-review'
    if (folder / 'escalation.json').is_file():return None, ['AGENT_REVIEW_DONE_FOR_THIS_RUN']
    rows = delegable(pack, settings.priorities, escalated_before(workspace))
    if not rows:return None, ['NO_DELEGABLE_ROWS']
    base = {'rule': 'review', 'policy_sha256': digest, 'rows': len(rows), 'reviewers': settings.reviewers}
    if not (folder / 'packet.json').is_file():return {**base, 'action': 'packet'}, []
    verdicts = sorted(folder.glob('verdicts-*.json'))
    if len(verdicts) < settings.reviewers:return {**base, 'action': 'agents', 'have': len(verdicts)}, []
    return {**base, 'action': 'agree'}, []


def do_packet(workspace, latest, plan):
    from .review_agents import delegable, escalated_before, packet
    settings, _, _ = rule(workspace, 'review')
    pack_raw = (latest / 'review-pack.json').read_bytes()
    pack = json.loads(pack_raw)
    made, key_raw = packet(pack, pack_raw, latest.name, delegable(pack, settings.priorities, escalated_before(workspace)), settings.canaries)
    folder = latest / 'agent-review';folder.mkdir(exist_ok=True)
    (folder / 'packet.json').write_text(json.dumps(made.model_dump(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    keys = keys_folder(workspace);keys.mkdir(parents=True, exist_ok=True)
    (keys / f'{latest.name}-canary-key.json').write_bytes(key_raw)
    return {'step': 'review-packet', 'rows': len(made.rows), 'canaries': settings.canaries}


def do_agree(workspace, latest, plan):
    from . import flow
    from .review_agents import agree
    from .review_pack import checked, merge
    settings, digest, _ = rule(workspace, 'review')
    folder = latest / 'agent-review'
    packet_raw = (folder / 'packet.json').read_bytes()
    key_raw = (keys_folder(workspace) / f'{latest.name}-canary-key.json').read_bytes()
    raws = [p.read_bytes() for p in sorted(folder.glob('verdicts-*.json'))]
    decisions, escalation = agree(packet_raw, key_raw, raws, settings, digest)
    (folder / 'escalation.json').write_text(json.dumps(escalation.model_dump(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    result = {'step': 'agree-review', 'status': escalation.status, 'ok': len(escalation.agreed_ok), 'escalated': len(escalation.escalated)}
    if decisions and decisions['decisions']:
        previous = flow.decisions(workspace)
        merged = checked(merge(json.loads(previous[-1].read_text(encoding='utf-8')) if previous else None, decisions))
        target = Path(workspace) / 'reviews' / f'decisions-{latest.name}-agents.json'
        target.parent.mkdir(exist_ok=True)
        target.write_text(json.dumps(merged, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        basis = Basis(**decisions['decisions'][0]['delegation'])
        found = log(workspace, 'review', FLOW_AGENT, basis, target, f'P2 {len(escalation.agreed_ok)}件をOK、{len(escalation.escalated)}件を人へ')
        result['auto_decision'] = found.id
    return result
