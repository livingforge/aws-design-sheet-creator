"""Rule reading: a diagram ledger written by rule, so that a draft never waits for an agent to write one by hand.

A ledger written by hand must name the document exactly, carry its extraction hash and give every drawing one entry
that satisfies the contract; a weaker agent loses hours there and the draft never comes out. `propose` gives every
element of a document a disposition from what the parser already knows: its kind, its text and alternative text
read with the service dictionary, the frames around it and the ends its line records or its place suggests. `start`
writes that ledger to the document's part under the author `agent:aws-design flow draft` (model `rules`), and
`write_missing` does so for every document a draft reads. The result always passes the ledger check. It is a draft's
reading: the coverage warns READ_BY_RULE, an agent may correct it and put its own name on it, and the final mode
never takes it as a worker's reading (docs/draft-mode.md 3.5).
"""
import json
import re
import unicodedata
from collections import Counter
from pathlib import Path

from .delegation import DRAFT_AGENT
from .fileio import write_atomic

MODEL = 'rules'
ZONE_CODE = re.compile(r'(?<![a-z0-9-])([a-z]{2}(?:-gov)?-[a-z]+-\d)([a-z])?(?![a-z0-9])')
REGION_NAMES = (('東京', 'ap-northeast-1'), ('大阪', 'ap-northeast-3'), ('tokyo', 'ap-northeast-1'), ('osaka', 'ap-northeast-3'),
                ('バージニア', 'us-east-1'), ('virginia', 'us-east-1'))
# What a frame's words say it bounds, tried in this order; a frame none of them fits bounds something OTHER.
FRAME_WORDS = (('SUBNET', re.compile(r'(?i)subnet|サブネット')), ('VPC', re.compile(r'(?i)(?<![a-z])vpc(?![a-z])')),
               ('ACCOUNT', re.compile(r'(?i)アカウント|(?<![a-z])account')),
               ('ENVIRONMENT', re.compile(r'(?i)環境|(?<![a-z])environment')),
               ('ON_PREMISES', re.compile(r'(?i)オンプレ|データセンタ|社内|拠点|on-?prem')))
LEGEND = re.compile(r'(?i)凡例|(?<![a-z])legend')
ACTORS = (('OPERATOR', re.compile(r'(?i)管理者|運用者|運用担当|保守|(?<![a-z])(?:operator|admin)')),
          ('USER', re.compile(r'(?i)利用者|ユーザ|顧客|受講者|学生|職員|会員|(?<![a-z])(?:users?|clients?)(?![a-z])')),
          ('EXTERNAL_SYSTEM', re.compile(r'(?i)外部システム|他システム|連携先|(?<![a-z])external')))
# A label longer than this is a note about the system, not the name of one thing in it.
LABEL_LENGTH = 60
# The service of a part of the system whose label names no AWS service: the design decides it, the rule does not guess.
UNKNOWN_SERVICE = '未定'


class InputError(ValueError):
    pass


# A dictionary service of several namespaces: the words of a label that say which one it is (EventBridge Scheduler).
NAMESPACE_WORDS = {'eventbridge': ((re.compile(r'(?i)scheduler|スケジューラ'), 'Scheduler'), (re.compile(r'(?i)pipes?(?![a-z])|パイプ'), 'Pipes'))}
BRACKETED = re.compile(r'[(（\[［][^)）\]］]*[)）\]］]')


def service_name(key, text=''):
    """The ledger's name for a dictionary service. One CloudFormation type when exactly one realises it (a family
    such as `AWS::EC2::VPCEndpoint*` is its base type); else the namespace, never the first of several types: the
    rule cannot tell an Aurora instance from its cluster, and a wrong type misleads whoever corrects the reading."""
    from .service_mentions import TYPES
    types = TYPES[key]
    for pattern, namespace in NAMESPACE_WORDS.get(key, ()):
        if pattern.search(text):return namespace
    if len(types) == 1 and not types[0].endswith('::'):return types[0].rstrip('*')
    return types[0].split('::')[1]


def region_of(text):
    """(region code, zone letter or None) a text names, or None."""
    plain = unicodedata.normalize('NFKC', text).lower()
    if (m := ZONE_CODE.search(plain)):return m.group(1), m.group(2)
    if 'リージョン' in plain or 'region' in plain:
        for word, code in REGION_NAMES:
            if word in plain:return code, None
    return None


def frame(text):
    """The BOUNDARY fields of a frame from its words."""
    place = region_of(text)
    if place and place[1]:return {'boundary': 'AZ', 'value': place[0] + place[1]}
    for boundary, pattern in FRAME_WORDS:
        if pattern.search(text):return {'boundary': boundary}
    if place:return {'boundary': 'REGION', 'value': place[0]}
    return None


def named(text):
    """What a label names: a RESOURCE by the service dictionary, an ACTOR by its words, a LEGEND, or nothing (None)."""
    from .service_mentions import detect
    if LEGEND.search(text):return {'disposition': 'LEGEND'}
    if len(text) > LABEL_LENGTH:return None
    # Words in brackets say what the thing is for, not what it is: `VPC エンドポイント（S3）` is an endpoint.
    keys = detect(BRACKETED.sub(' ', text)) or detect(text)
    if keys:
        entry = {'disposition': 'RESOURCE', 'service': service_name(keys[0], text)}
        if len(keys) > 1:entry['reason'] = '名前が複数のサービスに当たる（' + '、'.join(service_name(k) for k in keys) + '）。最初のものにした'
        return entry
    for kind, pattern in ACTORS:
        if pattern.search(text):return {'disposition': 'ACTOR', 'actor_kind': kind}
    return None


def propose(found):
    """One LedgerDocument (as a dict) for a document's drawings, every element with one disposition by rule, and what
    an agent should confirm: lines whose ends were taken from their place or not found, and labels naming several services."""
    from .diagram_ledger import is_line, line_points, near
    graphs = {r: v for v, visual in found.visuals.items() if visual['graph'] for r in visual['sources']}
    frames = {r for ref, chain in found.frames.items() for r in chain if found.elements[r]['kind'] != 'group'}
    elements, confirm = [], Counter()
    for ref, e in found.elements.items():
        text = ' '.join(t for t in (e['text'], e['alt']) if t)
        entry = {'ref': ref}
        if e['kind'] == 'group':entry['disposition'] = 'GROUP'
        elif e['kind'] in ('node', 'edge'):
            visual = found.visuals.get(e.get('visual')) or {}
            seen = e.get('method') == 'vision' and visual.get('state') == 'read' and bool(visual.get('evidence'))
            entry.update(visual=e['visual'], reading='vision' if seen else 'parser')
            if e['kind'] == 'edge':entry.update(disposition='CONNECTION', line='OTHER')
            else:entry.update(named(text) or {'disposition': 'ANNOTATION'})
            if entry['disposition'] == 'LEGEND':entry['disposition'] = 'ANNOTATION'
        elif e['kind'] == 'picture' and ref in graphs:entry.update(disposition='EXPANDED', visual=graphs[ref])
        elif is_line(e):
            ends = e['ends'] if len(e['ends']) == 2 and all(e['ends']) else None
            points = line_points(e)
            if ends:entry.update(disposition='CONNECTION', line='OTHER')
            elif points:
                guess = [[e['ends'][i]] if e['ends'] and e['ends'][i] else near(found, p, ref) for i, p in enumerate(points)]
                if all(len(g) == 1 for g in guess) and guess[0] != guess[1]:
                    entry.update(disposition='CONNECTION', line='OTHER', ends=[guess[0][0], guess[1][0]],
                                 reason='原本に線端の記録がなく、線の両端の位置にある図形から決めた')
                    confirm['line_ends_from_place'] += 1
            if 'disposition' not in entry:
                entry.update(disposition='ANNOTATION', reason='両端の図形を決められない線。接続を表すなら view の near= を見て CONNECTION にする')
                confirm['lines_without_ends'] += 1
        elif ref in frames:
            # A frame bounds what it holds; one that names a service and no place is that resource drawn as a frame.
            bounds = frame(text)
            what = None if bounds else named(text)
            if bounds:entry.update(disposition='BOUNDARY', **bounds)
            elif what and what['disposition'] == 'RESOURCE':entry.update(what)
            else:entry.update(disposition='BOUNDARY', boundary='OTHER')
        elif e['kind'] == 'picture' and not text:
            entry.update(disposition='ANNOTATION', reason='文字も代替テキストもない画像。規則では読まない（大きな画像は画像の仕分けで見る）')
        else:entry.update((named(text) if text else None) or {'disposition': 'ANNOTATION'})
        if entry.get('reason', '').startswith('名前が複数'):confirm['labels_naming_several_services'] += 1
        elements.append(entry)
    labels(found, elements)
    components(found, elements, confirm)
    mapped = any(x['disposition'] in ('RESOURCE', 'ACTOR', 'BOUNDARY', 'CONNECTION') for x in elements)
    document = {'document': found.document, 'extraction_sha256': found.sha256, 'contains_architecture': mapped,
                'reason': '規則による下書きの読み取り（図形の種類・文字・枠・線端から決めた。エージェントも人も確かめていない）', 'elements': elements}
    if found.structure_content_hash and any(x.get('visual') or x['ref'].startswith('v:') for x in elements):
        document['structure_content_hash'] = found.structure_content_hash
    return document, dict(confirm)


def labels(found, elements):
    """An icon grouped with its name label is one thing drawn once: the icon (a picture with alternative text) carries
    the disposition, and the label beside it is a note, not a second resource."""
    by_ref = {x['ref']: x for x in elements}
    members = {}
    for ref, e in found.elements.items():
        if e.get('group'):members.setdefault(e['group'], []).append(ref)
    for group, refs in members.items():
        icons = [r for r in refs if found.elements[r]['kind'] == 'picture' and by_ref[r]['disposition'] in ('RESOURCE', 'ACTOR')]
        if len(icons) != 1:continue
        for r in refs:
            entry = by_ref[r]
            if r != icons[0] and found.elements[r]['kind'] != 'picture' and entry['disposition'] in ('RESOURCE', 'ACTOR'):
                by_ref[r].clear()
                by_ref[r].update(ref=r, disposition='ANNOTATION', reason=f'{icons[0]} のアイコンと同じグループにある名前のラベル')


def components(found, elements, confirm):
    """A labelled box that a line joins, on a sheet that speaks of infrastructure, is a part of the system even when its
    label is no AWS name (a load balancer, a database server): the design must answer for it. The rule cannot say
    which service it becomes, so it is a RESOURCE whose service is the one a role word suggests, else 未定."""
    from .diagram_ledger import AWS_WORDS, is_line, page
    from .service_mentions import hints
    from .source_set import INFRA_WORDS
    by_ref = {x['ref']: x for x in elements}
    text = lambda ref:' '.join(t for t in (found.elements[ref]['text'], found.elements[ref]['alt']) if t)
    speaking = {page(ref) for ref, x in by_ref.items()
                if x['disposition'] in ('RESOURCE', 'ACTOR') or x.get('boundary') not in (None, 'OTHER') or INFRA_WORDS.search(text(ref)) or AWS_WORDS.search(text(ref))}
    joined = {end for ref, x in by_ref.items() if x['disposition'] == 'CONNECTION' for end in (x.get('ends') or found.elements[ref]['ends']) if end}
    for ref in joined:
        entry, source = by_ref.get(ref), found.elements.get(ref)
        if not entry or entry['disposition'] != 'ANNOTATION' or source['kind'] in ('group', 'picture') or is_line(source):continue
        label = text(ref)
        if not label or len(label) > LABEL_LENGTH or page(ref) not in speaking:continue
        suggested = hints(label)
        entry.update(disposition='RESOURCE', service=service_name(suggested[0]) if len(suggested) == 1 else UNKNOWN_SERVICE,
                     reason='線でつながる部品。名前がAWSのサービス名でないので、規則ではサービスを決められない。'
                            '設計入力でAWSのリソースにするか、外部システム・利用者なら台帳を ACTOR に直す')
        confirm['components_without_service_name'] += 1


def notes_only(found, codes):
    """The reading of last resort: every element a note, saying why. It passes any check, so a draft is never stuck on
    a drawing the rules read into something the check refuses."""
    reason = f"規則による読み取りが検査を通らなかった（{'、'.join(codes)}）ため、全要素を注記にした。構成を描く文書なら view を見て処置を書く"
    return {'document': found.document, 'extraction_sha256': found.sha256, 'contains_architecture': False, 'reason': reason,
            'elements': [{'ref': ref, 'disposition': 'ANNOTATION'} for ref in found.elements]}


def ledger_bytes(found, document=None):
    from pydantic import ValidationError
    from .diagram_ledger import Ledger, dump
    confirm = {}
    if document is None:
        try:
            document, confirm = propose(found)
            Ledger.model_validate({'contract': 'diagram-ledger/1', 'author': {'actor': DRAFT_AGENT, 'model': MODEL}, 'documents': [document]})
        except ValidationError:document, confirm = notes_only(found, ['CONTRACT_INVALID']), {'notes_only': 1}
    ledger = Ledger.model_validate({'contract': 'diagram-ledger/1', 'author': {'actor': DRAFT_AGENT, 'model': MODEL}, 'documents': [document]})
    return ledger, dump(ledger.model_dump(exclude_none=True, exclude_defaults=True)), confirm


def by_rule(ledger):return ledger.author.actor.strip() == DRAFT_AGENT


# Failures a draft lets pass as warnings: the ARP4 structure review belongs to the final mode.
DRAFT_TOLERATED = ('STRUCTURE_NOT_ACCEPTED',)


def failing(ledger, drawings, document):
    """Codes that fail a draft's reading of one document."""
    from .diagram_ledger import check
    return sorted({r['code'] for r in check(ledger, drawings, [document]).rows if r['severity'] == 'FAIL'} - set(DRAFT_TOLERATED))


def context(workspace):
    """(config, the approved set's path, the drawings of its CURRENT documents) of a draft workspace of part ledgers."""
    from . import flow
    from .diagram_ledger import read_documents, single
    workspace = Path(workspace);config = flow.load(workspace)
    if not flow.is_draft(config):
        raise InputError('FINAL_MODE: a rule reading is a draft; the final mode needs readings by two independent workers and a review')
    if single(workspace):raise InputError('SINGLE_LEDGER: the workspace keeps one ledger in diagrams/ledger.json; rule readings are written per document')
    approved = workspace / 'sources' / 'set.json'
    if not config.get('arp_root') or not approved.is_file():
        raise InputError('NO_SOURCE_SET: run aws-design flow run all first; it makes the draft source set')
    return config, approved, read_documents(Path(config['arp_root']), approved.read_bytes())


def write(workspace, found, drawings):
    """Write one document's rule reading to its part and say what it holds."""
    from .diagram_ledger import part_of
    ledger, raw, confirm = ledger_bytes(found)
    left = failing(ledger, drawings, found.document)
    if left:
        ledger, raw, _ = ledger_bytes(found, notes_only(found, left));confirm = {'notes_only': 1}
        left = failing(ledger, drawings, found.document)
    if left:raise InputError(f"RULE_READING_FAILED: {found.document}: {', '.join(left)}")
    part = part_of(workspace, found.document)
    write_atomic(part.first, raw)
    counts = Counter(e.disposition for e in ledger.documents[0].elements)
    # Which drawings each count is about, by what the rule wrote as its reason: look at these in `diagram view` first.
    marks = (('line_ends_from_place', '原本に線端'), ('lines_without_ends', '両端の図形'), ('labels_naming_several_services', '名前が複数'),
             ('components_without_service_name', '線でつながる部品'))
    refs = {key: [e.ref for e in ledger.documents[0].elements if e.reason.startswith(mark)][:30] for key, mark in marks if key in confirm}
    return {'document': found.document, 'ledger': str(part.first), 'elements': len(found.elements), 'dispositions': dict(sorted(counts.items())),
            **({'to_confirm': confirm, 'to_confirm_refs': refs} if confirm else {})}


def not_current(document, drawings):
    known = sorted(d for d, f in drawings.items() if f.elements)
    return InputError(f'INPUT_DOCUMENT_NOT_CURRENT: {document} is not a CURRENT document with drawings in sources/set.json. Use a document ID exactly as '
                      f'aws-design flow status names it; do not write a ledger for it. CURRENT documents with drawings: {json.dumps(known[:30], ensure_ascii=False)}'
                      + (f' and {len(known) - 30} more' if len(known) > 30 else ''))


def start(workspace, document, replace=False):
    """Write the rule reading of one document. An existing reading is kept unless `replace`, which retires it."""
    from .diagram_ledger import part_of, record_adoption, retire
    _, _, drawings = context(workspace)
    found = drawings.get(document)
    if found is None or not found.elements:raise not_current(document, drawings)
    part = part_of(workspace, document)
    retired = None
    if part.first.is_file():
        if not replace:raise InputError(f'LEDGER_EXISTS: {part.first} exists; fix it, or give --replace to retire it and start again from the rule reading')
        digest, author, where = retire(part, 'ledger')
        record_adoption(part, action='RETIRE', retired_reading='ledger', retired_sha256=digest, retired_author=author, retired_to=where,
                        actor=DRAFT_AGENT, reason='aws-design diagram start --replace：規則による読み取りから始め直す')
        retired = where
    return {**write(workspace, found, drawings), **({'retired': retired} if retired else {})}


def needed(workspace, drawings, triage):
    """Documents a draft reads whose part has no reading, or holds a rule reading that no longer passes (the document
    was imported again): the ones `write_missing` writes."""
    from .diagram_ledger import InputError as LedgerError, load, part_of
    from .diagram_triage import needs_reading
    out = []
    for document in needs_reading(triage):
        if document not in drawings:continue
        path = part_of(workspace, document).first
        if not path.is_file():out.append(document);continue
        try:ledger = load(path.read_bytes())
        except LedgerError:continue
        if by_rule(ledger) and failing(ledger, drawings, document):out.append(document)
    return out


def write_missing(workspace):
    """The step of `run all`: a rule reading for every document a draft reads that has none."""
    from .diagram_triage import current
    _, _, drawings = context(workspace)
    written = [write(workspace, drawings[d], drawings) for d in needed(workspace, drawings, current(workspace))]
    return {'step': 'read-diagrams', 'author': DRAFT_AGENT, 'written': written}
