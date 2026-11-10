"""Asks: the decisions a design still needs from people, asked one decision at a time, in order, and brought back.

The design input marks why each open setting is open: `cause` on an UNDECIDED setting says
whose move it is (OWNER_DECISION, WAITS_FOR a known event, EXTERNAL_DATA to be supplied,
DESIGNER_TASK, BUILD_NOTE for what the tool or the input's form left open), and `ask` names the
decision it belongs to. Only the first three reach people; designer tasks and build notes are
listed, never asked. An agent drafts the ledger (asks/ledger.json): per decision, the question
in the answerer's words, background quoting document cells, options with their impact and
the settings each one decides, the audience, the due date, what it depends on or waits for.
A different agent reviews it. Then the machine runs it: `check` grounds every quote in its
cells and applies every option to a copy of the input, `status` derives each decision's
state from the files, `sheet` sends the ready ones in order (overdue first, then what the
go-live, a requirement or most settings hang on) as one sheet per audience with at most a
few questions and a meeting agenda for decisions shared by several, `record` reads answers
back, says in words what each answer will set and refuses what fails a check, and `apply`
writes the answers into a new copy of the input with the record as their source. Decisions
are made only by the people named in the answers; agents never answer.
"""
import argparse
import copy
import hashlib
import json
import re
import sys
import unicodedata
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

ID = r'^[a-z][a-z0-9_-]{0,63}$'
ASKED = ('OWNER_DECISION', 'WAITS_FOR', 'EXTERNAL_DATA')
CAUSES = ASKED + ('DESIGNER_TASK', 'BUILD_NOTE')
CAUSES_JA = {'OWNER_DECISION': '発注者などの判断', 'WAITS_FOR': '時期が決まっている判断', 'EXTERNAL_DATA': '外部から受け取る値',
             'DESIGNER_TASK': '設計者の宿題', 'BUILD_NOTE': '構築時の注意'}
KIND_OF = {'OWNER_DECISION': 'DECISION', 'WAITS_FOR': 'DECISION', 'EXTERNAL_DATA': 'DATA_REQUEST'}
STATES_JA = {'INACTIVE': '前の回答待ち（条件付き）', 'NOT_NEEDED': '不要になった', 'BLOCKED': '先に決める判断がある', 'WAITING': '条件待ち',
             'READY': '聞ける', 'SENT': '回答待ち', 'HELD': '保留', 'ANSWERED': '回答済み（未反映）', 'APPLIED': '反映済み'}
RESOLVED = ('ANSWERED', 'APPLIED')
HOLD_WORDS = {'保留', 'hold'}
PER_SHEET = 6


class InputError(ValueError):
    pass


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Background(Strict):
    text: str = Field(min_length=1)
    source: str = Field(min_length=1, description='DOCUMENT_ID#s1-C5 of the cells that say it')
    quote: str = Field(min_length=1, description='words the cited cells hold; checked against them')


class Effect(Strict):
    resource_id: str = Field(pattern=ID)
    property: str = Field(min_length=1, description='setting name, or a path a/0/b into a composite value')
    value: JsonValue = None
    mode: Literal['LITERAL', 'OMITTED', 'DESIGNER_TASK'] = 'LITERAL'

    @model_validator(mode='after')
    def shape(self):
        if self.mode != 'LITERAL' and self.value is not None:raise ValueError('only a LITERAL effect carries a value')
        return self


class Option(Strict):
    id: str = Field(pattern=r'^[a-z0-9]{1,8}$')
    label: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    proposed: bool = False
    effects: list[Effect] = Field(default_factory=list)
    follow_up: list[str] = Field(default_factory=list)


class FreeValue(Strict):
    kind: Literal['integer', 'number', 'string']
    unit: str = ''
    minimum: float | None = None
    maximum: float | None = None
    pattern: str | None = None
    hint: str = ''
    effects: list[Effect] = Field(default_factory=list, description='settings the answered value goes into; value stays null')


class OnlyIf(Strict):
    ask: str = Field(pattern=ID)
    option: str = Field(pattern=r'^[a-z0-9]{1,8}$')


class Ask(Strict):
    id: str = Field(pattern=ID)
    kind: Literal['DECISION', 'DATA_REQUEST']
    title: str = Field(min_length=1)
    question: str = Field(min_length=1)
    audience: list[str] = Field(min_length=1)
    background: list[Background] = Field(min_length=1)
    options: list[Option] = Field(default_factory=list)
    free_value: FreeValue | None = None
    settles: str = Field(default='', description='what the answer decides, in the answerer\'s words')
    due: date | None = None
    waits_for: str | None = None
    depends_on: list[str] = Field(default_factory=list)
    only_if: OnlyIf | None = None
    critical: bool = Field(default=False, description='go-live depends on it')
    requirement_conflict: list[str] = Field(default_factory=list, description='requirement IDs a current value or option breaks')


class Author(Strict):
    actor: str = Field(min_length=1)
    model: str = ''


class Ledger(Strict):
    contract: Literal['ask-ledger/1']
    author: Author | None = None
    asks: list[Ask] = Field(min_length=1)


class Entry(Strict):
    ask: str = Field(pattern=ID)
    action: Literal['ANSWER', 'HOLD', 'READY']
    option: str | None = None
    value: JsonValue = None
    note: str = ''
    by: str = Field(min_length=1)
    on: date


class Records(Strict):
    contract: Literal['ask-records/1']
    sequence: int = Field(ge=1)
    ledger_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    recorded_at: str
    workbook_sha256: str | None = None
    entries: list[Entry] = Field(min_length=1)


class AskReview(Strict):
    contract: Literal['ask-review/1']
    ledger_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    decision: Literal['accepted', 'rejected']
    actor: str = Field(min_length=1)
    author: str | None = None
    reason: str = Field(min_length=1)
    recorded_at: str


class Sheet(Strict):
    audience: str
    asks: list[str]
    workbook: str
    markdown: str


class Batch(Strict):
    contract: Literal['ask-batch/1']
    sequence: int = Field(ge=1)
    ledger_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    created_at: str
    sheets: list[Sheet] = Field(default_factory=list)
    agenda: list[str] = Field(default_factory=list)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def stamp(now=None):return (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
def esc(key):return str(key).replace('~', '~0').replace('/', '~1')
def plain(text):return unicodedata.normalize('NFKC', str(text)).strip().casefold()


# --- What is open in the input --------------------------------------------------------------------

def pending(design, environment=None):
    """Open settings with their place: UNDECIDED ones and any carrying a cause, top level, overrides and composite leaves."""
    out = []
    names = {r.get('id'): r.get('name') or r.get('id') for r in design.get('resources', [])}
    types = {r.get('id'): r.get('type') for r in design.get('resources', [])}

    def visit(resource_id, path, setting, pointer):
        if not isinstance(setting, dict):return
        open_ = setting.get('status', 'DECIDED') == 'UNDECIDED'
        if open_ or setting.get('cause'):
            out.append({'resource_id': resource_id, 'resource_name': names.get(resource_id, resource_id), 'type': types.get(resource_id),
                        'property': path, 'pointer': pointer, 'status': setting.get('status', 'DECIDED'), 'mode': setting.get('mode'),
                        'cause': setting.get('cause'), 'ask': setting.get('ask'), 'rationale': setting.get('rationale', '')})
        if setting.get('status', 'DECIDED') == 'DECIDED' and setting.get('mode') == 'COMPOSITE':
            leaves(resource_id, path, setting.get('value'), pointer + '/value')

    def leaves(resource_id, path, node, pointer):
        if isinstance(node, dict):
            if set(node) == {'$design'}:visit(resource_id, path, node['$design'], pointer + '/$design');return
            for k, v in node.items():leaves(resource_id, f'{path}/{k}', v, f'{pointer}/{esc(k)}')
        elif isinstance(node, list):
            for i, v in enumerate(node):leaves(resource_id, f'{path}/{i}', v, f'{pointer}/{i}')
    overridden = {}
    for i, env in enumerate(design.get('environments', []) or []):
        if environment is not None and env.get('id') != environment:continue
        for j, o in enumerate(env.get('overrides', []) or []):
            for name, s in (o.get('settings') or {}).items():
                overridden[(o.get('resource_id'), name)] = True
                visit(o.get('resource_id'), name, s, f'/environments/{i}/overrides/{j}/settings/{esc(name)}')
    for i, r in enumerate(design.get('resources', [])):
        for name, s in (r.get('settings') or {}).items():
            if (r.get('id'), name) not in overridden:visit(r.get('id'), name, s, f'/resources/{i}/settings/{esc(name)}')
    return out


def triage(design, environment=None):
    """Open settings sorted by cause: asked ones by ask ID, tasks and notes grouped, and those nobody classified."""
    out = {'asked': {}, 'DESIGNER_TASK': [], 'BUILD_NOTE': [], 'unclassified': [], 'unlinked': []}
    for p in pending(design, environment):
        cause = p['cause']
        if cause in ASKED:
            if p['ask']:out['asked'].setdefault(p['ask'], []).append(p)
            else:out['unlinked'].append(p)
        elif cause in ('DESIGNER_TASK', 'BUILD_NOTE'):out[cause].append(p)
        elif p['status'] == 'UNDECIDED':out['unclassified'].append(p)
    return out


# --- Applying answers to a copy of the input ------------------------------------------------------

def locate(design, environment, resource_id, path):
    """(container, key, is_leaf) of the setting or composite leaf an effect names; the override of the environment wins."""
    parts = path.split('/')
    top = parts[0]
    holder = None
    for env in design.get('environments', []) or []:
        if env.get('id') != environment:continue
        for o in env.get('overrides', []) or []:
            if o.get('resource_id') == resource_id and top in (o.get('settings') or {}):holder = o['settings']
    if holder is None:
        resource = next((r for r in design.get('resources', []) if r.get('id') == resource_id), None)
        if resource is None:raise InputError(f'UNKNOWN_RESOURCE: {resource_id}')
        holder = resource.setdefault('settings', {})
    if len(parts) == 1:return holder, top, False
    if top not in holder or holder[top].get('mode') != 'COMPOSITE':raise InputError(f'NOT_A_COMPOSITE: {resource_id}.{top}')
    node = holder[top]['value']
    for part in parts[1:-1]:
        node = step(node, part, resource_id, path)
        if isinstance(node, dict) and set(node) == {'$design'}:
            if node['$design'].get('mode') != 'COMPOSITE':raise InputError(f'PATH_NOT_FOUND: {resource_id}.{path}')
            node = node['$design']['value']
    last = parts[-1]
    if isinstance(node, list):
        if not last.isdigit() or int(last) >= len(node):raise InputError(f'PATH_NOT_FOUND: {resource_id}.{path}')
        return node, int(last), True
    if not isinstance(node, dict) or last not in node:raise InputError(f'PATH_NOT_FOUND: {resource_id}.{path}')
    return node, last, True


def step(node, part, resource_id, path):
    if isinstance(node, list) and part.isdigit() and int(part) < len(node):return node[int(part)]
    if isinstance(node, dict) and part in node:return node[part]
    raise InputError(f'PATH_NOT_FOUND: {resource_id}.{path}')


def put(design, environment, effect, value, source_id, why):
    """Set what an answer decides: a whole setting, or a leaf of a composite value (kept in a `$design` node)."""
    container, key, leaf = locate(design, environment, effect.resource_id, effect.property)
    current = container[key] if isinstance(container, list) or key in container else None
    old = current['$design'] if leaf and isinstance(current, dict) and set(current) == {'$design'} else None if leaf else current
    keep = {k: old[k] for k in ('decision_ids', 'classification') if isinstance(old, dict) and k in old}
    if effect.mode == 'DESIGNER_TASK':new = {'status': 'UNDECIDED', 'cause': 'DESIGNER_TASK', 'rationale': why, 'sources': [source_id], **keep}
    elif effect.mode == 'OMITTED':new = {'mode': 'OMITTED', 'rationale': why, 'sources': [source_id], **keep}
    else:new = {'mode': 'COMPOSITE' if isinstance(value, (dict, list)) else 'LITERAL', 'value': value, 'rationale': why, 'sources': [source_id], **keep}
    container[key] = {'$design': new} if leaf else new


def answer_effects(ask, entry):
    """(effect, value) pairs an answer decides."""
    if entry.option is not None:
        option = next(o for o in ask.options if o.id == entry.option)
        return [(e, e.value) for e in option.effects]
    return [(e, entry.value) for e in ask.free_value.effects]


def validate_design(design):
    from .document_v11 import SchemaInput
    try:SchemaInput.model_validate(design)
    except ValidationError as exc:
        first = exc.errors(include_input=False)[0]
        raise InputError('EFFECT_INVALID: ' + '/'.join(map(str, first['loc']))[:120] + ' ' + str(first.get('msg', ''))[:120]) from None


# --- Checking a ledger ----------------------------------------------------------------------------

def load_ledger(raw):
    try:return Ledger.model_validate_json(raw)
    except ValidationError as exc:
        raise InputError('CONTRACT_INVALID: ' + ', '.join('/'.join(map(str, e['loc'])) + ' ' + e['type'] for e in exc.errors(include_input=False))[:400]) from None


def check(ledger, design, environment, library=None, answered=()):
    """Findings that stop a ledger: coverage of the input's open settings, form of each ask, grounding and effects."""
    findings = []
    add = lambda code, target, detail='': findings.append({'code': code, 'target': target, 'detail': detail})
    asks = {a.id: a for a in ledger.asks}
    if len(asks) != len(ledger.asks):add('DUPLICATE_ASK', ','.join(sorted({a.id for a in ledger.asks if [b.id for b in ledger.asks].count(a.id) > 1})))
    sorted_ = triage(design, environment)
    for p in sorted_['unclassified']:add('UNCLASSIFIED', f"{p['resource_id']}.{p['property']}", 'UNDECIDED に cause がない')
    for p in sorted_['unlinked']:add('ASK_MISSING', f"{p['resource_id']}.{p['property']}", f"cause {p['cause']} に ask がない")
    for ask_id, settings in sorted_['asked'].items():
        if ask_id not in asks:
            add('UNKNOWN_ASK', ask_id, ', '.join(f"{p['resource_id']}.{p['property']}" for p in settings[:5]));continue
        for p in settings:
            if KIND_OF[p['cause']] != asks[ask_id].kind:add('KIND_MISMATCH', f"{p['resource_id']}.{p['property']}", f"{p['cause']} → {asks[ask_id].kind}")
    for a in ledger.asks:
        target = a.id
        if a.kind == 'DATA_REQUEST' and a.free_value is None:add('DATA_REQUEST_WITHOUT_VALUE', target)
        if a.kind == 'DECISION' and len(a.options) < 2 and a.free_value is None:add('NO_CHOICE', target, '選択肢2つ以上か、値の回答欄が要る')
        if len({o.id for o in a.options}) != len(a.options):add('DUPLICATE_OPTION', target)
        if sum(o.proposed for o in a.options) > 1:add('MORE_THAN_ONE_PROPOSAL', target)
        if any(plain(o.id) in HOLD_WORDS or plain(o.label) in HOLD_WORDS for o in a.options):add('HOLD_IS_NOT_AN_OPTION', target, '保留は常に選べるので選択肢にしない')
        for d in a.depends_on:
            if d not in asks:add('UNKNOWN_DEPENDENCY', target, d)
        if a.only_if:
            trigger = asks.get(a.only_if.ask)
            option = next((o for o in trigger.options if o.id == a.only_if.option), None) if trigger else None
            if option is None or a.id not in option.follow_up:add('FOLLOW_UP_MISMATCH', target, f'{a.only_if.ask}.{a.only_if.option}')
        for o in a.options:
            for f in o.follow_up:
                if f not in asks or asks[f].only_if is None or (asks[f].only_if.ask, asks[f].only_if.option) != (a.id, o.id):add('FOLLOW_UP_MISMATCH', target, f)
        settings = sorted_['asked'].get(a.id, [])
        wanted = {(p['resource_id'], p['property']) for p in settings}
        if wanted and not a.settles:add('SETTLES_MISSING', target, '答えで決まることを答える人の言葉で書く')
        forms = [(f'option {o.id}', o.effects) for o in a.options if o.effects or wanted] + ([('free_value', a.free_value.effects)] if a.free_value else [])
        if a.id in answered:forms = []  # answered decisions already left the input's open settings
        for label, effects in forms:
            got = {(e.resource_id, e.property) for e in effects}
            if wanted - got:add('OPTION_NOT_COVERING', f'{target} {label}', ', '.join(f'{r}.{p}' for r, p in sorted(wanted - got))[:200])
            if got - wanted:add('EFFECT_OUTSIDE_ASK', f'{target} {label}', ', '.join(f'{r}.{p}' for r, p in sorted(got - wanted))[:200])
        if library is not None:
            for i, b in enumerate(a.background):
                status, detail = library.judge(b.source, [b.quote])
                if status in ('NOT_FOUND', 'NOT_FOUND_IN_DOCUMENT', 'CITES_NOT_CURRENT'):add('BACKGROUND_' + status, f'{target} background/{i}', detail)
    cycle = find_cycle(asks)
    if cycle:add('DEPENDENCY_CYCLE', ' → '.join(cycle))
    if not findings:
        # Each way of answering, applied alone to a copy, must still be a valid input.
        for a in ledger.asks:
            if a.id in answered:continue
            trials = [(f'option {o.id}', [(e, e.value) for e in o.effects]) for o in a.options if o.effects]
            if a.free_value and a.free_value.effects:trials.append(('free_value', [(e, sample(a.free_value)) for e in a.free_value.effects]))
            for label, pairs in trials:
                trial = copy.deepcopy(design)
                try:
                    for effect, value in pairs:put(trial, environment, effect, value, 'ask-check', 'check')
                    trial.setdefault('sources', []).append({'id': 'ask-check', 'title': 'check', 'locator': 'asks/ledger.json'})
                    validate_design(trial)
                except InputError as exc:add('EFFECT_INVALID', f'{a.id} {label}', str(exc)[:200])
    return {'status': 'FAIL' if findings else 'PASS', 'findings': findings,
            'counts': {'asks': len(ledger.asks), 'asked_settings': sum(len(v) for v in sorted_['asked'].values()),
                       'designer_tasks': len(sorted_['DESIGNER_TASK']), 'build_notes': len(sorted_['BUILD_NOTE']),
                       'unclassified': len(sorted_['unclassified'])}}


def sample(free):
    """A value of the right kind for checking that the effects accept an answer."""
    if free.kind == 'string':return 'example'
    low = free.minimum if free.minimum is not None else 1
    return int(low) if free.kind == 'integer' else float(low)


def find_cycle(asks):
    seen, stack = set(), []

    def visit(node):
        if node in stack:return stack[stack.index(node):] + [node]
        if node in seen or node not in asks:return None
        seen.add(node);stack.append(node)
        nexts = list(asks[node].depends_on) + ([asks[node].only_if.ask] if asks[node].only_if else [])
        for n in nexts:
            found = visit(n)
            if found:return found
        stack.pop()
        return None
    for a in asks:
        found = visit(a)
        if found:return found
    return None


# --- Workspace files ------------------------------------------------------------------------------

def folder(workspace):return Path(workspace) / 'asks'
def ledger_path(workspace):return folder(workspace) / 'ledger.json'
def review_path(workspace, digest):return folder(workspace) / f'review-{digest[:12]}.json'


def read_records(workspace):
    base = folder(workspace) / 'records'
    return [Records.model_validate_json(p.read_bytes()) for p in sorted(base.glob('*.json'))] if base.is_dir() else []


def read_batches(workspace):
    base = folder(workspace) / 'batches'
    return [Batch.model_validate_json((p / 'manifest.json').read_bytes()) for p in sorted(base.iterdir()) if (p / 'manifest.json').is_file()] if base.is_dir() else []


def next_sequence(workspace):
    return 1 + max([r.sequence for r in read_records(workspace)] + [b.sequence for b in read_batches(workspace)] + [0])


def workspace_parts(workspace):
    from . import flow
    config = flow.load(workspace)
    input_path = flow.generation_input(workspace, config)
    if not input_path.is_file():raise InputError('NO_INPUT')
    design = json.loads(input_path.read_text(encoding='utf-8'))
    return config, input_path, design


def library_for(config, workspace):
    if not config.get('arp_root') or not (Path(workspace) / 'sources' / 'set.json').is_file():return None
    from .grounding import Library
    return Library.from_arp(Path(config['arp_root']), (Path(workspace) / 'sources' / 'set.json').read_bytes())


# --- States and order -----------------------------------------------------------------------------

def states(ledger, records, batches, design, environment, today):
    """Per ask: state, whether overdue, the open settings it decides and the latest answer."""
    asked = triage(design, environment)['asked']
    latest, events = {}, sorted([(r.sequence, i, e) for r in records for i, e in enumerate(r.entries)], key=lambda x: (x[0], x[1]))
    for seq, _, e in events:latest[e.ask] = (seq, e)
    sent = {}
    for b in batches:
        for s in b.sheets:
            for a in s.asks:sent[a] = b.sequence
        for a in b.agenda:sent[a] = b.sequence
    asks = {a.id: a for a in ledger.asks}
    out = {}

    def state_of(ask):
        if ask.id in out:return out[ask.id]['state']
        seq, e = latest.get(ask.id, (0, None))
        if ask.only_if:
            _, trigger = latest.get(ask.only_if.ask, (0, None))
            if trigger is None or trigger.action != 'ANSWER':state = 'INACTIVE'
            elif trigger.option != ask.only_if.option:state = 'NOT_NEEDED'
            else:state = None
        else:state = None
        if state is None:
            if e is not None and e.action == 'ANSWER':state = 'ANSWERED' if asked.get(ask.id) else 'APPLIED'
            elif e is not None and e.action == 'HOLD':state = 'HELD'
            elif any(state_of(asks[d]) not in RESOLVED for d in ask.depends_on if d in asks):state = 'BLOCKED'
            elif ask.waits_for and not (e is not None and e.action == 'READY'):state = 'WAITING'
            elif sent.get(ask.id, 0) > seq:state = 'SENT'
            else:state = 'READY'
        out[ask.id] = {'state': state, 'state_ja': STATES_JA[state], 'settings': asked.get(ask.id, []),
                       'overdue': bool(ask.due and ask.due < today and state not in RESOLVED + ('NOT_NEEDED', 'INACTIVE')),
                       'answer': e.model_dump(mode='json') if e is not None and e.action == 'ANSWER' else None}
        return state
    for a in ledger.asks:state_of(a)
    return out


def weight(ledger, found):
    """How much waits on each ask: its own open settings plus every ask that depends on it, directly or through a follow-up."""
    asks = {a.id: a for a in ledger.asks}
    after = {a.id: set() for a in ledger.asks}
    for a in ledger.asks:
        for d in a.depends_on + ([a.only_if.ask] if a.only_if else []):
            if d in after:after[d].add(a.id)

    def reach(node, seen):
        for n in after[node]:
            if n not in seen:seen.add(n);reach(n, seen)
        return seen
    return {a: len(found[a]['settings']) + sum(1 + len(found[b]['settings']) for b in reach(a, set())) for a in asks}


def order(ledger, found, among=('READY',)):
    """Asks in the given states in the order to ask them: overdue, go-live, requirement conflicts, most waiting on them, earliest due."""
    w = weight(ledger, found)
    ready = [a for a in ledger.asks if found[a.id]['state'] in among]
    return sorted(ready, key=lambda a: (not found[a.id]['overdue'], not a.critical, not a.requirement_conflict, -w[a.id], a.due or date.max, a.id))


def plan(ledger, found, per_sheet=PER_SHEET):
    """Sheets per audience of at most per_sheet asks, and the agenda for asks several audiences share."""
    sheets, agenda = {}, []
    for a in order(ledger, found):
        if len(a.audience) > 1:agenda.append(a)
        else:
            queue = sheets.setdefault(a.audience[0], [])
            if len(queue) < per_sheet:queue.append(a)
    return sheets, agenda


# --- Words for people -----------------------------------------------------------------------------

def option_lines(a):
    lines = [f"{o.id}：{o.label}{'（設計者の案）' if o.proposed else ''} ― {o.impact}" for o in a.options]
    if a.free_value:
        f = a.free_value
        limits = '、'.join(x for x in (f'{f.minimum:g}以上' if f.minimum is not None else '', f'{f.maximum:g}以下' if f.maximum is not None else '') if x)
        lines.append(f"値を書く：{f.hint or '値'}{'（' + f.unit + '）' if f.unit else ''}{'、' + limits if limits else ''}")
    lines.append('保留：理由を補足欄に書く')
    return lines


def background_lines(a):return [f"{b.text}（{b.source}）" for b in a.background]


def effect_words(ask, entry, ledger):
    """What an answer does to the input and to the other asks, said for the person who gave it and listed for the designer."""
    if entry.action == 'HOLD':return f"保留（{entry.note or '理由の記載なし'}）。設定は未決のまま残り、この判断を待つ判断も止まったまま", []
    if entry.action == 'READY':return '条件がそろった。次の質問票で聞く', []
    pairs = answer_effects(ask, entry)
    label = next(o.label for o in ask.options if o.id == entry.option) if entry.option is not None else f'{entry.value}{ask.free_value.unit}'
    technical = [f"{e.resource_id}.{e.property} = {json.dumps(v, ensure_ascii=False) if e.mode == 'LITERAL' else e.mode}" for e, v in pairs]
    said = f"「{label}」"
    if pairs:said += f"。{ask.settles or '関係する設定'}が決まる（設定 {len(pairs)}件）"
    else:said += '。設定の変更はなく、方針の決定として記録する'
    follow = [f for o in ask.options if o.id == entry.option for f in o.follow_up]
    if follow:said += '。続けて聞く判断：' + '、'.join(follow)
    after = [a.id for a in ledger.asks if ask.id in a.depends_on]
    if after:said += '。この回答を待っていた判断：' + '、'.join(after)
    return said, technical


def sheet_rows(asks):
    for n, a in enumerate(asks, 1):
        yield {'番号': n, '判断ID': a.id, '問い': f"{'【ご依頼】' if a.kind == 'DATA_REQUEST' else ''}{a.title}\n{a.question}", '背景': '\n'.join(background_lines(a)),
               '選択肢と影響': '\n'.join(option_lines(a)), '答えで決まること': a.settles or '（設定はない。方針の判断）',
               '期限': a.due.isoformat() if a.due else '', '回答': '', '値': '', '補足・保留の理由': '', '回答者': '', '回答日': ''}


def heading(asks):
    kinds = {a.kind for a in asks}
    return '質問とご依頼' if kinds == {'DECISION', 'DATA_REQUEST'} else 'ご依頼' if kinds == {'DATA_REQUEST'} else '質問'


HEADERS = ['番号', '判断ID', '問い', '背景', '選択肢と影響', '答えで決まること', '期限', '回答', '値', '補足・保留の理由', '回答者', '回答日']


def workbook(asks, ledger_sha, sequence, audience):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation
    book = Workbook();ws = book.active;ws.title = '質問'
    ws.append([f'{audience} 様への{heading(asks)}（第{sequence}回）。「回答」に選択肢の記号か「保留」を書いてください。値を答える問いは「回答」に「値」、「値」の欄に値を書いてください。']);ws.append([])
    ws.append(HEADERS)
    for c in ws[3]:c.font = Font(bold=True);c.fill = PatternFill('solid', fgColor='DDEBF7')
    for i, row in enumerate(sheet_rows(asks), 4):
        ws.append([row[h] for h in HEADERS])
        a = asks[i - 4]
        choices = [o.id for o in a.options] + ['保留'] + (['値'] if a.free_value else [])
        dv = DataValidation(type='list', formula1='"' + ','.join(choices) + '"', allow_blank=True);ws.add_data_validation(dv);dv.add(f'H{i}')
        for c in ws[i]:c.alignment = Alignment(wrap_text=True, vertical='top')
    for col, width in zip('ABCDEFGHIJKL', (5, 16, 40, 50, 50, 30, 11, 8, 14, 30, 12, 12)):ws.column_dimensions[col].width = width
    key = book.create_sheet('key');key.append(['ledger_sha256', ledger_sha]);key.append(['sequence', sequence]);key.append(['audience', audience]);key.sheet_state = 'hidden'
    return book


def sheet_markdown(asks, sequence, audience):
    lines = [f'# {audience} 様への{heading(asks)}（第{sequence}回）', '', '各問いに、選択肢の記号か「保留」（理由を添えて）でお答えください。設計者の案は「設計者の案」と書いてあります。', '']
    for row, a in zip(sheet_rows(asks), asks):
        lines += [f"## {row['番号']}. {'【ご依頼】' if a.kind == 'DATA_REQUEST' else ''}{a.title}（{a.id}）", '', a.question, '']
        if a.due:lines += [f'期限：{a.due.isoformat()}', '']
        lines += ['背景：', ''] + [f'- {x}' for x in background_lines(a)] + ['', '選択肢と影響：', ''] + [f'- {x}' for x in option_lines(a)]
        lines += ['', f"答えで決まること：{row['答えで決まること']}", '']
    return '\n'.join(lines) + '\n'


def agenda_markdown(asks, sequence):
    lines = [f'# 会議の議題（第{sequence}回）', '', '複数の部署にまたがる判断。質問票ではなく会議で決め、決定を `aws-design asks record --ask` で記録する。', '']
    for a in asks:
        lines += [f'## {a.title}（{a.id}）', '', f"出席が要る：{'、'.join(a.audience)}", '', a.question, ''] + [f'- {x}' for x in background_lines(a)]
        lines += [''] + [f'- {x}' for x in option_lines(a)] + ['']
    return '\n'.join(lines) + '\n'


def tasks_markdown(sorted_):
    lines = ['# 設計者の宿題と構築時の注意', '', '人に聞かない項目。宿題は設計者が決め、構築時の注意は構築の手順に入れる。', '']
    for cause in ('DESIGNER_TASK', 'BUILD_NOTE'):
        items = sorted_[cause]
        lines += [f'## {CAUSES_JA[cause]}（{len(items)}件）', '']
        groups = {}
        for p in items:groups.setdefault(p['property'], []).append(p)
        for prop, ps in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            lines.append(f"- {prop}（{len(ps)}件）：" + '、'.join(p['resource_name'] for p in ps[:8]) + ('…' if len(ps) > 8 else ''))
            notes = sorted({p['rationale'] for p in ps if p['rationale']})
            lines += [f'  - {n}' for n in notes[:3]]
        lines.append('')
    return '\n'.join(lines) + '\n'


def board(ledger, found, sorted_, today):
    w = weight(ledger, found)
    lines = [f'# 判断の一覧（{today.isoformat()} 時点）', '', '| 順 | 判断 | 宛先 | 状態 | 期限 | 待っている設定・判断 | 前提 |', '|---|---|---|---|---|---|---|']
    ranked = {a.id: i for i, a in enumerate(order(ledger, found, ('READY', 'SENT', 'HELD', 'WAITING', 'BLOCKED')), 1)}
    for a in sorted(ledger.asks, key=lambda a: (ranked.get(a.id, 999), a.id)):
        f = found[a.id]
        due = (a.due.isoformat() if a.due else '') + ('（期限切れ）' if f['overdue'] else '')
        before = '、'.join(x for x in (', '.join(a.depends_on), f'条件：{a.waits_for}' if a.waits_for else '', f'{a.only_if.ask} が {a.only_if.option} のとき' if a.only_if else '') if x)
        lines.append(f"| {ranked.get(a.id, '')} | {a.title}（{a.id}） | {'、'.join(a.audience)} | {f['state_ja']} | {due} | {w[a.id]} | {before} |")
    lines += ['', f"人に聞かない項目：設計者の宿題 {len(sorted_['DESIGNER_TASK'])}件、構築時の注意 {len(sorted_['BUILD_NOTE'])}件（tasks.md）。"
              + (f"原因が書かれていない未決 {len(sorted_['unclassified'])}件。" if sorted_['unclassified'] else '')]
    return '\n'.join(lines) + '\n'


# --- Commands -------------------------------------------------------------------------------------

def load_all(workspace, today=None):
    config, input_path, design = workspace_parts(workspace)
    path = ledger_path(workspace)
    if not path.is_file():raise InputError('NO_LEDGER: asks/ledger.json not found; an agent drafts it from aws-design asks start')
    raw = path.read_bytes();ledger = load_ledger(raw)
    records, batches = read_records(workspace), read_batches(workspace)
    found = states(ledger, records, batches, design, config['environment'], today or date.today())
    return config, input_path, design, raw, ledger, records, batches, found


CHECKED = {}


def checked_once(workspace, config, raw, input_path, ledger, design, answered):
    """The ledger check, kept for this process while the ledger, the input, the source set and the answered asks are the same."""
    source_set = Path(workspace) / 'sources' / 'set.json'
    key = (sha(raw), sha(input_path.read_bytes()), config['environment'], sha(source_set.read_bytes()) if source_set.is_file() else None, tuple(sorted(answered)))
    if key not in CHECKED:CHECKED[key] = check(ledger, design, config['environment'], library_for(config, workspace), answered)
    return CHECKED[key]


def status(workspace, today=None):
    """Everything the flow and people need: ledger check, review, states and the next action."""
    today = today or date.today()
    config, input_path, design = workspace_parts(workspace)
    sorted_ = triage(design, config['environment'])
    report = {'unclassified': len(sorted_['unclassified']) + len(sorted_['unlinked']), 'designer_tasks': len(sorted_['DESIGNER_TASK']),
              'build_notes': len(sorted_['BUILD_NOTE']), 'asked_settings': sum(len(v) for v in sorted_['asked'].values())}
    path = ledger_path(workspace)
    if report['unclassified']:return {**report, 'next': 'CLASSIFY'}
    if not path.is_file():return {**report, 'next': 'DRAFT' if sorted_['asked'] else 'NOTHING_TO_ASK'}
    raw = path.read_bytes()
    try:ledger = load_ledger(raw)
    except InputError as exc:return {**report, 'next': 'FIX_LEDGER', 'findings': [{'code': str(exc).split(':', 1)[0], 'target': 'asks/ledger.json', 'detail': str(exc)[:300]}]}
    records, batches = read_records(workspace), read_batches(workspace)
    found = states(ledger, records, batches, design, config['environment'], today)
    answered = {a for a, f in found.items() if f['state'] in RESOLVED}
    checked = checked_once(workspace, config, raw, input_path, ledger, design, answered)
    report.update(ledger_sha256=sha(raw), check=checked['status'], findings=checked['findings'][:50],
                  states={a: {k: f[k] for k in ('state', 'overdue')} for a, f in found.items()},
                  counts={s: sum(f['state'] == s for f in found.values()) for s in STATES_JA if any(f['state'] == s for f in found.values())},
                  overdue=sorted(a for a, f in found.items() if f['overdue']))
    if checked['status'] == 'FAIL':return {**report, 'next': 'FIX_LEDGER'}
    review = review_path(workspace, sha(raw))
    reviewed = json.loads(review.read_text(encoding='utf-8')) if review.is_file() else None
    current = reviewed is not None and reviewed.get('ledger_sha256') == sha(raw)
    # A draft asks once from a ledger that passes its check; the independent review belongs to the final mode,
    # though a review recorded for these bytes still counts, a rejection included.
    if config.get('mode') == 'draft' and not current:report['unreviewed'] = True
    elif not current:return {**report, 'next': 'REVIEW', 'author': ledger.author.actor if ledger.author else None}
    elif reviewed['decision'] == 'rejected':return {**report, 'next': 'FIX_LEDGER', 'rejected': reviewed['reason']}
    if any(f['state'] == 'ANSWERED' for f in found.values()):return {**report, 'next': 'APPLY'}
    if any(f['state'] == 'READY' for f in found.values()):return {**report, 'next': 'SHEET'}
    if any(f['state'] == 'SENT' for f in found.values()):return {**report, 'next': 'WAIT_FOR_ANSWERS'}
    return {**report, 'next': 'DONE'}


def start(workspace):
    """What an agent drafts the ledger from: the open settings grouped by ask, and the tasks and notes nobody is asked."""
    config, input_path, design = workspace_parts(workspace)
    sorted_ = triage(design, config['environment'])
    pick = lambda p: {k: p[k] for k in ('resource_id', 'resource_name', 'type', 'property', 'pointer', 'cause', 'rationale')}
    return {'input': str(input_path), 'environment': config['environment'],
            'asks': {a: [pick(p) for p in ps] for a, ps in sorted(sorted_['asked'].items())},
            'unclassified': [pick(p) for p in sorted_['unclassified'] + sorted_['unlinked']],
            'designer_tasks': len(sorted_['DESIGNER_TASK']), 'build_notes': len(sorted_['BUILD_NOTE']),
            'contract': 'aws-design contract schema --kind ask-ledger'}


def review(workspace, decision, actor, reason, now=None):
    from .delegation import agent
    raw = ledger_path(workspace).read_bytes();ledger = load_ledger(raw)
    actor = agent(actor)
    author = ledger.author.actor if ledger.author else None
    if author and agent(author) == actor:raise InputError('REVIEWER_IS_AUTHOR: use an independent reviewer')
    if decision == 'accepted':
        found = status(workspace)
        if found.get('check') == 'FAIL':raise InputError('CHECK_FAILED: a ledger that fails aws-design asks check cannot be accepted')
    record = AskReview(contract='ask-review/1', ledger_sha256=sha(raw), decision=decision, actor=actor, author=author, reason=reason.strip(), recorded_at=stamp(now))
    path = review_path(workspace, sha(raw));path.write_text(record.model_dump_json(indent=2) + '\n', encoding='utf-8')
    return {'review': str(path), 'decision': decision}


def make_sheets(workspace, per_sheet=PER_SHEET, only=(), today=None, now=None):
    config, input_path, design, raw, ledger, records, batches, found = load_all(workspace, today)
    # No sheet leaves before the ledger passes its check and an independent review accepted it, even for chosen asks.
    if status(workspace, today)['next'] not in ('SHEET', 'WAIT_FOR_ANSWERS', 'APPLY', 'DONE'):raise InputError('NOT_READY: aws-design asks status shows what comes first')
    if only:
        chosen = [a for a in ledger.asks if a.id in only]
        if len(chosen) != len(set(only)):raise InputError('UNKNOWN_ASK: ' + ', '.join(sorted(set(only) - {a.id for a in chosen})))
        bad = [a.id for a in chosen if found[a.id]['state'] in RESOLVED + ('NOT_NEEDED', 'INACTIVE', 'BLOCKED')]
        if bad:raise InputError('NOT_ASKABLE: ' + ', '.join(bad))
        sheets, agenda = {}, []
        for a in chosen:(agenda.append(a) if len(a.audience) > 1 else sheets.setdefault(a.audience[0], []).append(a))
    else:sheets, agenda = plan(ledger, found, per_sheet)
    if not sheets and not agenda:raise InputError('NOTHING_READY')
    sequence = next_sequence(workspace)
    out = folder(workspace) / 'batches' / f'{sequence:03d}';out.mkdir(parents=True)
    listed = []
    for audience, asks in sheets.items():
        name = re.sub(r'[\\/:*?"<>|\s]+', '_', audience)
        book = workbook(asks, sha(raw), sequence, audience);book.save(out / f'{name}.xlsx');book.close()
        (out / f'{name}.md').write_text(sheet_markdown(asks, sequence, audience), encoding='utf-8')
        listed.append(Sheet(audience=audience, asks=[a.id for a in asks], workbook=f'{name}.xlsx', markdown=f'{name}.md'))
    if agenda:(out / 'agenda.md').write_text(agenda_markdown(agenda, sequence), encoding='utf-8')
    batch = Batch(contract='ask-batch/1', sequence=sequence, ledger_sha256=sha(raw), created_at=stamp(now), sheets=listed, agenda=[a.id for a in agenda])
    (out / 'manifest.json').write_text(batch.model_dump_json(indent=2) + '\n', encoding='utf-8')
    sorted_ = triage(design, config['environment'])
    found = states(ledger, records, read_batches(workspace), design, config['environment'], today or date.today())
    (folder(workspace) / 'board.md').write_text(board(ledger, found, sorted_, today or date.today()), encoding='utf-8')
    (folder(workspace) / 'tasks.md').write_text(tasks_markdown(sorted_), encoding='utf-8')
    return {'batch': str(out), 'sheets': {s.audience: s.asks for s in listed}, 'agenda': [a.id for a in agenda]}


def read_workbook(path, ledger_sha):
    from openpyxl import load_workbook
    book = load_workbook(path, data_only=True)
    try:
        if 'key' not in book.sheetnames:raise InputError('NOT_AN_ASK_SHEET')
        key = {r[0]: r[1] for r in book['key'].iter_rows(values_only=True) if r and r[0]}
        if key.get('ledger_sha256') != ledger_sha:raise InputError('STALE_SHEET: the ledger changed after this sheet was made; make a new sheet')
        ws = book['質問'];rows = list(ws.iter_rows(min_row=4, values_only=True))
        return [dict(zip(HEADERS, r)) for r in rows if r and r[1]], key
    finally:book.close()


def parse_answer(ask, answer, value, note, by, on):
    from .delegation import InputError as NameError_, person_name
    try:by = person_name(by, 'ANSWERER')
    except NameError_ as exc:raise InputError(str(exc)) from None
    word = plain(answer)
    if word in HOLD_WORDS:
        if not str(note or '').strip():raise InputError(f'HOLD_REASON_REQUIRED: {ask.id}')
        return Entry(ask=ask.id, action='HOLD', note=str(note).strip(), by=by, on=on)
    option = next((o for o in ask.options if plain(o.id) == word), None)
    if option is not None:return Entry(ask=ask.id, action='ANSWER', option=option.id, note=str(note or '').strip(), by=by, on=on)
    if ask.free_value is None or (word not in ('値', 'value') and not (word == '' and value not in (None, ''))):
        raise InputError(f'UNKNOWN_CHOICE: {ask.id} {answer}')
    return Entry(ask=ask.id, action='ANSWER', value=typed(ask, value), note=str(note or '').strip(), by=by, on=on)


def typed(ask, value):
    f = ask.free_value
    text = unicodedata.normalize('NFKC', str(value if value is not None else '')).strip()
    if not text:raise InputError(f'VALUE_REQUIRED: {ask.id}')
    if f.kind == 'string':
        if f.pattern and not re.fullmatch(f.pattern, text):raise InputError(f'VALUE_PATTERN: {ask.id}')
        return text
    number = text.replace(',', '')
    for unit in filter(None, [f.unit]):number = number.removesuffix(unit).strip()
    try:got = int(number) if f.kind == 'integer' else float(number)
    except ValueError:raise InputError(f'VALUE_NOT_A_NUMBER: {ask.id}') from None
    if f.minimum is not None and got < f.minimum or f.maximum is not None and got > f.maximum:raise InputError(f'VALUE_OUT_OF_RANGE: {ask.id}')
    return got


def as_date(value, default):
    if value in (None, ''):return default
    if isinstance(value, datetime):return value.date()
    if isinstance(value, date):return value
    try:return date.fromisoformat(unicodedata.normalize('NFKC', str(value)).strip().replace('/', '-'))
    except ValueError:raise InputError(f'DATE_INVALID: {value}') from None


def record(workspace, entries_in, *, workbook_sha=None, dry_run=False, today=None, now=None):
    """Check answers, say what each will set, and keep them as a numbered record unless dry_run."""
    config, input_path, design, raw, ledger, records, batches, found = load_all(workspace, today)
    asks = {a.id: a for a in ledger.asks}
    entries = []
    for e in entries_in:
        ask = asks.get(e['ask'])
        if ask is None:raise InputError(f"UNKNOWN_ASK: {e['ask']}")
        state = found[ask.id]['state']
        if state in ('APPLIED', 'NOT_NEEDED', 'INACTIVE'):raise InputError(f'NOT_ANSWERABLE: {ask.id} is {state}')
        if e.get('ready'):
            if state not in ('WAITING', 'HELD'):raise InputError(f'NOT_WAITING: {ask.id} is {state}')
            from .delegation import InputError as NameError_, person_name
            try:by = person_name(e['by'], 'RECORDER')
            except NameError_ as exc:raise InputError(str(exc)) from None
            entries.append(Entry(ask=ask.id, action='READY', note=str(e.get('note') or '').strip(), by=by, on=e['on']));continue
        if state == 'BLOCKED':raise InputError(f'BLOCKED: {ask.id} waits for ' + ', '.join(ask.depends_on))
        entries.append(parse_answer(ask, e.get('answer'), e.get('value'), e.get('note'), e.get('by'), e['on']))
    if not entries:raise InputError('NO_ANSWERS')
    # Every answer not yet applied, this one included, must leave a valid input.
    trial = copy.deepcopy(design);trial.setdefault('sources', []).append({'id': 'ask-check', 'title': 'check', 'locator': 'asks/records'})
    pending_answers = {a: f['answer'] for a, f in found.items() if f['state'] == 'ANSWERED'}
    pending_answers.update({e.ask: e.model_dump(mode='json') for e in entries if e.action == 'ANSWER'})
    for ask_id, answer in pending_answers.items():
        for effect, value in answer_effects(asks[ask_id], Entry.model_validate(answer)):put(trial, config['environment'], effect, value, 'ask-check', 'check')
    if any(e.action == 'ANSWER' for e in entries):validate_design(trial)
    echo = []
    for e in entries:
        said, technical = effect_words(asks[e.ask], e, ledger)
        echo.append({'ask': e.ask, 'title': asks[e.ask].title, 'by': e.by, 'on': e.on.isoformat(), 'says': said, 'sets': technical})
    if dry_run:return {'dry_run': True, 'echo': echo}
    sequence = next_sequence(workspace)
    out = folder(workspace) / 'records';out.mkdir(parents=True, exist_ok=True)
    rec = Records(contract='ask-records/1', sequence=sequence, ledger_sha256=sha(raw), recorded_at=stamp(now), workbook_sha256=workbook_sha, entries=entries)
    (out / f'{sequence:03d}.json').write_text(rec.model_dump_json(indent=2) + '\n', encoding='utf-8')
    return {'record': str(out / f'{sequence:03d}.json'), 'echo': echo}


def apply(workspace, today=None):
    """Write every answered, not yet applied decision into a new copy of the input and point the flow at it."""
    from . import flow
    config, input_path, design, raw, ledger, records, batches, found = load_all(workspace, today)
    asks = {a.id: a for a in ledger.asks}
    answered = {a: f['answer'] for a, f in found.items() if f['state'] == 'ANSWERED'}
    if not answered:raise InputError('NOTHING_TO_APPLY')
    if config.get('policy_pack'):raise InputError('POLICY_INPUT: apply answers to the source input before the policy pack; not supported yet')
    where = {e.ask: r.sequence for r in records for e in r.entries if e.action == 'ANSWER'}
    new = copy.deepcopy(design)
    for ask_id, answer in sorted(answered.items()):
        entry = Entry.model_validate(answer)
        source_id = f'ask-records-{where[ask_id]:03d}'
        if not any(s.get('id') == source_id for s in new.get('sources', [])):
            new.setdefault('sources', []).append({'id': source_id, 'title': f'判断の回答の記録 第{where[ask_id]}回', 'locator': f'asks/records/{where[ask_id]:03d}.json'})
        label = next(o.label for o in asks[ask_id].options if o.id == entry.option) if entry.option else f'{entry.value}'
        why = f'判断 {ask_id}「{asks[ask_id].title}」の回答（{entry.by}、{entry.on.isoformat()}）：{label}'
        for effect, value in answer_effects(asks[ask_id], entry):put(new, config['environment'], effect, value, source_id, why)
    validate_design(new)
    stem = re.sub(r'-asks-\d{3}$', '', input_path.stem)
    target = input_path.with_name(f'{stem}-asks-{max(where[a] for a in answered):03d}{input_path.suffix}')
    if target.exists():raise InputError(f'OUTPUT_EXISTS: {target.name}')
    target.write_text(json.dumps(new, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    cfg_path = Path(workspace) / flow.CONFIG
    cfg = json.loads(cfg_path.read_text(encoding='utf-8'))
    cfg['input'] = target.relative_to(Path(workspace)).as_posix()
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {'input': str(target), 'applied': sorted(answered), 'previous_input': str(input_path)}


def entries_from_workbook(workspace, path, by=None, on=None):
    raw = ledger_path(workspace).read_bytes()
    rows, key = read_workbook(path, sha(raw))
    default_on = on or date.today()
    out = []
    for r in rows:
        if r.get('回答') in (None, '') and r.get('値') in (None, ''):continue
        out.append({'ask': str(r['判断ID']).strip(), 'answer': r.get('回答') or '', 'value': r.get('値'), 'note': r.get('補足・保留の理由'),
                    'by': r.get('回答者') or by, 'on': as_date(r.get('回答日'), default_on)})
    return out, sha(Path(path).read_bytes())


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design asks', description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    for name, text in (('start', 'open settings grouped by ask, to draft the ledger from'), ('status', 'ledger check, review, states and the next action'),
                       ('check', 'check the ledger against the input and the cited cells'), ('board', 'write asks/board.md and asks/tasks.md'),
                       ('apply', 'write answered decisions into a new copy of the input')):
        p = sub.add_parser(name, help=text);p.add_argument('--workspace', required=True);p.add_argument('--today', help='YYYY-MM-DD, for overdue')
    p = sub.add_parser('review', help='record an independent review of the ledger');p.add_argument('--workspace', required=True)
    p.add_argument('--decision', choices=['accepted', 'rejected'], required=True);p.add_argument('--actor', required=True);p.add_argument('--reason', required=True)
    p = sub.add_parser('sheet', help='make the next sheets and agenda in order');p.add_argument('--workspace', required=True)
    p.add_argument('--per-sheet', type=int, default=PER_SHEET);p.add_argument('--ask', action='append', default=[], help='send these asks only');p.add_argument('--today')
    p = sub.add_parser('record', help='record answers from a returned sheet, or one answer given in a meeting');p.add_argument('--workspace', required=True)
    p.add_argument('--workbook');p.add_argument('--ask');p.add_argument('--answer', help='option, 保留 or 値');p.add_argument('--value');p.add_argument('--note', default='')
    p.add_argument('--by', help='the person who answered, when the sheet does not say');p.add_argument('--on', help='YYYY-MM-DD');p.add_argument('--dry-run', action='store_true')
    p.add_argument('--today')
    p = sub.add_parser('ready', help='record that what an ask waits for has happened, or that a held ask may be asked again')
    p.add_argument('--workspace', required=True);p.add_argument('--ask', required=True);p.add_argument('--by', required=True);p.add_argument('--note', default='')
    p.add_argument('--on');p.add_argument('--today')
    args = parser.parse_args(argv)
    try:
        today = as_date(getattr(args, 'today', None), date.today())
        ws = Path(args.workspace)
        if args.command == 'start':result = start(ws)
        elif args.command == 'status':result = status(ws, today)
        elif args.command == 'check':
            found = status(ws, today)
            result = {k: found.get(k) for k in ('check', 'findings', 'unclassified', 'asked_settings', 'designer_tasks', 'build_notes')}
            text = json.dumps(result, ensure_ascii=False, indent=2) + '\n';sys.stdout.buffer.write(text.encode('utf-8'))
            return 0 if found.get('check') == 'PASS' else 2
        elif args.command == 'board':
            config, input_path, design, raw, ledger, records, batches, found = load_all(ws, today)
            sorted_ = triage(design, config['environment'])
            (folder(ws) / 'board.md').write_text(board(ledger, found, sorted_, today), encoding='utf-8')
            (folder(ws) / 'tasks.md').write_text(tasks_markdown(sorted_), encoding='utf-8')
            result = {'board': str(folder(ws) / 'board.md'), 'tasks': str(folder(ws) / 'tasks.md')}
        elif args.command == 'review':result = review(ws, args.decision, args.actor, args.reason)
        elif args.command == 'sheet':result = make_sheets(ws, args.per_sheet, tuple(args.ask), today)
        elif args.command == 'record':
            on = as_date(args.on, today)
            if args.workbook:
                entries, digest = entries_from_workbook(ws, args.workbook, args.by, on)
                result = record(ws, entries, workbook_sha=digest, dry_run=args.dry_run, today=today)
            elif args.ask:result = record(ws, [{'ask': args.ask, 'answer': args.answer or '', 'value': args.value, 'note': args.note, 'by': args.by, 'on': on}],
                                          dry_run=args.dry_run, today=today)
            else:raise InputError('WORKBOOK_OR_ASK_REQUIRED')
        elif args.command == 'ready':
            result = record(ws, [{'ask': args.ask, 'ready': True, 'by': args.by, 'note': args.note, 'on': as_date(args.on, today)}], today=today)
        else:result = apply(ws, today)
        sys.stdout.buffer.write((json.dumps(result, ensure_ascii=False, indent=2, default=str) + '\n').encode('utf-8'))
        return 0
    except (InputError, OSError, json.JSONDecodeError) as exc:
        sys.stdout.buffer.write((json.dumps({'status': 'ERROR', 'message': str(exc) if isinstance(exc, InputError) else type(exc).__name__}, ensure_ascii=False) + '\n').encode('utf-8'))
        return 2
    except ValidationError as exc:
        message = 'CONTRACT_INVALID: ' + ', '.join('/'.join(map(str, e['loc'])) + ' ' + e['type'] for e in exc.errors(include_input=False))[:300]
        sys.stdout.buffer.write((json.dumps({'status': 'ERROR', 'message': message}, ensure_ascii=False) + '\n').encode('utf-8'))
        return 2


if __name__ == '__main__':
    sys.exit(main())
