"""Picture triage: which CURRENT documents draw the system, decided before anyone reads a drawing element by element.

A draft cannot afford two readings and a review of every document that holds a shape, and it cannot leave pictures
unseen either: an architecture diagram pasted as an image is the best evidence a design has. `build` looks at each
CURRENT document with drawings and sets aside, by rule, the pictures a parser already reads (text or alternative
text, or a graph ARP4 holds), small ones (icons, logos), pictures without a file and repeats of one image. Every other
picture is looked at once by an agent and recorded with `look` by the image's SHA-256 as ARCHITECTURE, NETWORK,
SCREENSHOT, TABLE, PHOTO, LOGO, OTHER or UNVIEWABLE, with the AWS services an architecture picture shows. A document
draws the system when its drawings name AWS or network things or hold a graph, its kind is ARCHITECTURE, or a picture
of it was seen to be an architecture or network diagram; only such documents with drawings other than unread
pictures get a reading in draft mode, and `draft_coverage` joins those readings, the triage and the design input.
The triage records what was seen; it is a draft's evidence, never a reviewed reading (docs/draft-mode.md 3.3).
"""
import argparse
import hashlib
import json
import struct
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, ValidationError

from .models import StrictModel

CONTRACT = 'diagram-triage/1'
Hash = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
LookKind = Literal['ARCHITECTURE', 'NETWORK', 'SCREENSHOT', 'TABLE', 'PHOTO', 'LOGO', 'OTHER', 'UNVIEWABLE']
KINDS_JA = {'ARCHITECTURE': '構成図', 'NETWORK': 'ネットワーク図', 'SCREENSHOT': '画面', 'TABLE': '表', 'PHOTO': '写真', 'LOGO': 'ロゴ',
            'OTHER': 'その他', 'UNVIEWABLE': '表示できない'}
DRAWS_SYSTEM = ('ARCHITECTURE', 'NETWORK')
Skip = Literal['HAS_TEXT', 'READ_IN_ARP4', 'NO_FILE', 'SMALL', 'DUPLICATE']
# A picture whose longer side is below MIN_SIDE pixels, or whose area is below MIN_AREA (a banner logo), is an icon or a
# logo; without a size, a file below MIN_BYTES is.
MIN_SIDE, MIN_AREA, MIN_BYTES = 160, 20_000, 20_000
# Formats an agent's image viewer opens; others are recorded UNVIEWABLE unless rendered to PNG first.
VIEWABLE = ('png', 'jpeg', 'gif', 'webp')
# Pictures handed to one triage run.
BATCH = 40


class InputError(ValueError):
    pass


class Look(StrictModel):
    sha256: Hash
    kind: LookKind
    services: list[str] = Field(default_factory=list, max_length=60)
    note: str = Field(default='', max_length=300)
    actor: str = Field(min_length=1)
    recorded_at: str


class Picture(StrictModel):
    ref: str
    sha256: Hash | None = None
    path: str | None = None
    format: str | None = None
    width: int | None = None
    height: int | None = None
    skipped: Skip | None = None


class TriageDocument(StrictModel):
    document: str
    extraction_sha256: Hash
    elements: int
    signs: dict[str, int] = Field(default_factory=dict)
    kind: str | None = None
    pictures: list[Picture] = Field(default_factory=list)
    # Whether it has drawings other than pictures without text: those need a reading of their own.
    readable: bool = False
    decision: Literal['ARCHITECTURE', 'NOT_ARCHITECTURE', 'PENDING']
    basis: Literal['SIGNALS', 'PICTURES', 'NOTHING']


class Triage(StrictModel):
    contract: Literal['diagram-triage/1']
    source_set_sha256: Hash
    documents: list[TriageDocument]
    looks: list[Look] = Field(default_factory=list)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def stamp():return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
def dump(value):return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
def triage_path(workspace):return Path(workspace) / 'diagrams' / 'triage.json'


def load(raw):
    try:return Triage.model_validate_json(raw)
    except ValidationError as exc:
        raise InputError('CONTRACT_INVALID: ' + ', '.join('/'.join(map(str, e['loc'])) + ' ' + e['type'] for e in exc.errors(include_input=False))[:300]) from None


def image_size(raw):
    """(format, width, height) from an image's header; the size is None where the header is not read."""
    if raw[:8] == b'\x89PNG\r\n\x1a\n' and len(raw) >= 24:return ('png', *struct.unpack('>II', raw[16:24]))
    if raw[:6] in (b'GIF87a', b'GIF89a') and len(raw) >= 10:return ('gif', *struct.unpack('<HH', raw[6:10]))
    if raw[:4] == b'RIFF' and raw[8:12] == b'WEBP':return ('webp', None, None)
    if raw[:2] == b'\xff\xd8':
        at = 2
        while at + 9 < len(raw):
            if raw[at] != 0xFF:at += 1;continue
            marker = raw[at + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:at += 2;continue
            length = struct.unpack('>H', raw[at + 2:at + 4])[0]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                height, width = struct.unpack('>HH', raw[at + 5:at + 9]);return ('jpeg', width, height)
            at += 2 + length
        return ('jpeg', None, None)
    if raw[:4] == b'\x01\x00\x00\x00' and raw[40:44] == b' EMF':return ('emf', None, None)
    if raw[:4] in (b'\xd7\xcd\xc6\x9a', b'\x01\x00\x09\x00'):return ('wmf', None, None)
    if raw[:2] == b'BM':return ('bmp', None, None)
    if raw[:4] in (b'II*\x00', b'MM\x00*'):return ('tiff', None, None)
    return (None, None, None)


def pictures_of(found, seen):
    """The pictures of one document, each with why it needs no look or what to look at. `seen` holds image hashes met
    earlier, so a repeat of one image is looked at once."""
    graphs = {r for v in found.visuals.values() if v['graph'] for r in v['sources']}
    out = []
    for ref, e in found.elements.items():
        if e['kind'] != 'picture':continue
        picture = Picture(ref=ref)
        path = found.picture_path(ref)
        if path is not None:
            raw = path.read_bytes();picture.sha256, picture.path = sha(raw), str(path)
            picture.format, picture.width, picture.height = image_size(raw)
        if e['alt'] or e['text']:picture.skipped = 'HAS_TEXT'
        elif ref in graphs:picture.skipped = 'READ_IN_ARP4'
        elif path is None:picture.skipped = 'NO_FILE'
        elif ((max(picture.width, picture.height) < MIN_SIDE or picture.width * picture.height < MIN_AREA) if picture.width and picture.height
              else path.stat().st_size < MIN_BYTES):
            picture.skipped = 'SMALL'
        elif picture.sha256 in seen:picture.skipped = 'DUPLICATE'
        else:seen.add(picture.sha256)
        out.append(picture)
    return out


def decide(doc, looks):
    """A document's decision and its basis from its signs, its kind and the looks recorded for its pictures."""
    if doc.signs.get('aws_named') or doc.signs.get('graphs') or doc.kind == 'ARCHITECTURE':return 'ARCHITECTURE', 'SIGNALS'
    wanted = [p for p in doc.pictures if p.sha256 and p.skipped in (None, 'DUPLICATE')]
    if any(looks[p.sha256].kind in DRAWS_SYSTEM for p in wanted if p.sha256 in looks):return 'ARCHITECTURE', 'PICTURES'
    if any(p.sha256 not in looks for p in wanted):return 'PENDING', 'PICTURES'
    return 'NOT_ARCHITECTURE', 'PICTURES' if wanted else 'NOTHING'


def build(workspace):
    """Write diagrams/triage.json for the approved set as it stands, keeping every look recorded before."""
    from . import flow
    from .diagram_ledger import architecture_signs, read_documents
    from .source_set import load_approved
    workspace = Path(workspace);config = flow.load(workspace)
    set_raw = (workspace / 'sources' / 'set.json').read_bytes()
    drawings = read_documents(Path(config['arp_root']), set_raw)
    kinds = {e.document_id: e.signals.kind for e in load_approved(set_raw).documents}
    path = triage_path(workspace)
    looks = load(path.read_bytes()).looks if path.is_file() else []
    by_sha = {k.sha256: k for k in looks}
    seen, documents = set(), []
    for document, found in sorted(drawings.items()):
        if not found.elements:continue
        pictures = pictures_of(found, seen)
        unread = {p.ref for p in pictures if p.skipped not in ('HAS_TEXT', 'READ_IN_ARP4')}
        doc = TriageDocument(document=document, extraction_sha256=found.sha256, elements=len(found.elements), signs=architecture_signs(found),
                             kind=kinds.get(document), pictures=pictures, readable=any(r not in unread for r in found.elements),
                             decision='PENDING', basis='NOTHING')
        doc.decision, doc.basis = decide(doc, by_sha)
        documents.append(doc)
    triage = Triage(contract=CONTRACT, source_set_sha256=sha(set_raw), documents=documents, looks=looks)
    path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(dump(triage.model_dump(exclude_none=True)))
    counts = Counter(d.decision for d in documents)
    return {'step': 'triage', 'triage': str(path), 'documents': dict(sorted(counts.items())), 'to_look': len(pending(triage))}


def stale(workspace, triage, drawings):
    """Why a triage no longer matches the approved set, or None."""
    set_path = Path(workspace) / 'sources' / 'set.json'
    if not set_path.is_file() or sha(set_path.read_bytes()) != triage.source_set_sha256:return 'SOURCE_SET_CHANGED'
    listed = {d.document: d.extraction_sha256 for d in triage.documents}
    current = {d: f.sha256 for d, f in drawings.items() if f.elements}
    return None if listed == current else 'DOCUMENTS_CHANGED'


def pending(triage):
    """Pictures still to look at: one per image, with the documents that hold it."""
    looked = {k.sha256 for k in triage.looks};out = {}
    for doc in triage.documents:
        for p in doc.pictures:
            if p.sha256 and p.skipped in (None, 'DUPLICATE') and p.sha256 not in looked:
                row = out.setdefault(p.sha256, {'image': p.sha256, 'path': p.path, 'format': p.format, 'refs': []})
                row['refs'].append(f'{doc.document}#{p.ref}')
    return [r for r in out.values() if r['path']]


def record_look(workspace, image, kind, services, note, actor):
    """Record what one picture shows, by its hash, and decide the documents again."""
    from .delegation import agent
    path = triage_path(workspace)
    if not path.is_file():raise InputError('NO_TRIAGE: run aws-design flow run all first')
    triage = load(path.read_bytes())
    known = {p.sha256: p for d in triage.documents for p in d.pictures if p.sha256}
    if image not in known:raise InputError(f'UNKNOWN_IMAGE: {image[:12]} is no picture of the triage')
    if services and kind not in DRAWS_SYSTEM:raise InputError('SERVICES_ONLY_FOR_DIAGRAMS: name services only for ARCHITECTURE or NETWORK')
    if kind != 'UNVIEWABLE' and known[image].format not in VIEWABLE:
        raise InputError(f'NOT_VIEWABLE: the image is {known[image].format or "of an unknown format"}; record UNVIEWABLE or render it to PNG in ARP4')
    looks = [k for k in triage.looks if k.sha256 != image]
    looks.append(Look(sha256=image, kind=kind, services=[s.strip() for s in services if s.strip()], note=note.strip(), actor=agent(actor), recorded_at=stamp()))
    by_sha = {k.sha256: k for k in looks}
    for doc in triage.documents:doc.decision, doc.basis = decide(doc, by_sha)
    triage.looks = looks
    path.write_bytes(dump(triage.model_dump(exclude_none=True)))
    return {'image': image, 'kind': kind, 'documents': sorted({d.document for d in triage.documents if any(p.sha256 == image for p in d.pictures)}),
            'to_look': len(pending(triage))}


def needs_reading(triage):
    """Documents a draft reads element by element: drawing the system, with drawings other than unread pictures."""
    return [d.document for d in triage.documents if d.decision == 'ARCHITECTURE' and d.readable]


# --- Flow stage and coverage in draft mode --------------------------------------------------------------

def flow_stage(workspace, config, q, drawings, approved):
    from .diagram_ledger import InputError as LedgerError, check, load as load_ledger, part_of
    from .flow import STALE_HELP, role, stage
    arp = config['arp_root']
    documents = {d: len(f.elements) for d, f in drawings.items() if f.elements}
    detail = f"図形・画像を含むCURRENTの文書 {len(documents)}件、要素 {sum(documents.values())}件"
    run_all = f'aws-design flow run all --workspace {q(workspace)}'
    path = triage_path(workspace)
    if not path.is_file():return stage('diagrams', 'TODO', '下書きモード：画像の仕分けがない。run all が図形の手がかりと画像の大きさで仕分ける。' + detail, run_all, action='triage')
    try:triage = load(path.read_bytes())
    except InputError as exc:return stage('diagrams', 'TODO', f'画像の仕分けを読めない（{str(exc)[:120]}）。run all が作り直す。' + detail, run_all, action='triage')
    why = stale(workspace, triage, drawings)
    if why:return stage('diagrams', 'TODO', f'画像の仕分けが古い（{why}）。run all が作り直す（記録した目視は画像の内容で引き継ぐ）。' + detail, run_all, action='triage')
    looks = pending(triage)
    if looks:
        batches = [looks[i:i + BATCH] for i in range(0, len(looks), BATCH)]
        command = (f'aws-design diagram look --workspace {q(workspace)} --image <SHA-256> --kind <ARCHITECTURE|NETWORK|SCREENSHOT|TABLE|PHOTO|LOGO|OTHER|UNVIEWABLE>'
                   ' [--service <サービス名>]... [--note <見たもの>] --actor <作成担当の名前>')
        runs = [{'pictures': batch, 'look': command, 'actor': f'作成担当の名前（{n}つ目）'} for n, batch in enumerate(batches, 1)]
        handoff = {'look': command, **({'pictures': looks} if len(runs) == 1 else {'runs': runs})}
        return stage('diagrams', 'WAITING_FOR_AGENT', f'下書きモード：目で見て種類を記録する画像 {len(looks)}件（1枚1回、構成図なら描かれたAWSサービスも）。' + detail,
                     command, agent=role('aws-design-author', 'diagram-triager', len(runs), handoff))
    common = f'--arp-root {q(arp)} --source-set {q(approved)}'
    readings, done = [], 0
    for document in needs_reading(triage):
        part = part_of(workspace, document)
        view = f'aws-design diagram view {common} --document {q(document)}'
        checking = f'aws-design diagram check {common} --ledger {q(part.first)} --for-document {q(document)}'
        run = {'document': document, 'output': str(part.first), 'check': checking, 'view': view, 'actor': '作成担当の名前',
               'draft': '下書きモード：この文書の読み取りは1つだけで、2つ目の読み取りと独立レビューは確定モードで行う'}
        if not part.first.is_file():readings.append({**run, 'why': '構成を描く文書の台帳がない'});continue
        try:ledger = load_ledger(part.first.read_bytes())
        except LedgerError as exc:readings.append({**run, 'why': f'台帳が契約を満たさない（{str(exc)[:120]}）'});continue
        found = check(ledger, drawings, [document])
        failing = sorted({r['code'] for r in found.rows if r['severity'] == 'FAIL'})
        if 'STRUCTURE_NOT_ACCEPTED' in failing:
            return stage('diagrams', 'TODO', f"{document}：{STALE_HELP['STRUCTURE_NOT_ACCEPTED']}。" + detail, f'aws-design diagram preflight {common} --ledger {q(part.first)}')
        if failing:readings.append({**run, 'why': f"台帳の検査が不合格：{'、'.join(failing)}", 'actor': ledger.author.actor});continue
        done += 1
    decisions = Counter(d.decision for d in triage.documents)
    summary = (f"構成を描く見込み {decisions.get('ARCHITECTURE', 0)}件（うち読む文書 {len(needs_reading(triage))}件）、"
               f"描かない見込み {decisions.get('NOT_ARCHITECTURE', 0)}件、見た画像 {len(triage.looks)}件")
    if readings:
        base = {'arp_root': arp, 'source_set': str(approved)}
        handoff = {**base, **readings[0]} if len(readings) == 1 else {**base, 'runs': readings}
        if len(readings) == 1:handoff.pop('why')
        return stage('diagrams', 'WAITING_FOR_AGENT', f"下書きモード：{readings[0]['why'] if len(readings) == 1 else f'読む文書 {len(readings)}件'}。{summary}。" + detail,
                     readings[0]['check'], agent=role('aws-design-author', 'diagram-extract-worker', len(readings), handoff))
    return stage('diagrams', 'DONE', f'下書き：{summary}、読んだ文書 {done}件（独立レビューは確定モード）。' + detail)


def service_keys(name):
    """Service keys a name a look recorded stands for: a CloudFormation type, or names the service dictionary knows."""
    from .service_mentions import LABELS, detect, type_holds
    name = str(name).strip()
    if '::' in name:return {k for k in LABELS if type_holds(k, name)}
    return set(detect(name))


def draft_coverage(workspace, arp_root, set_raw, design):
    """The diagram coverage of a draft: readings of the documents that need one, joined with the input as in the final
    mode but without the independent review, documents the triage set aside counted as out of scope, and the services
    architecture pictures show checked against the input. None when no CURRENT document has drawings."""
    from .diagram_ledger import (Design, Findings, InputError as LedgerError, asks_state, combined, coverage, design_counts,
                                 load as load_ledger, load_review, part_of, read_documents)
    from .service_mentions import in_design
    drawings = read_documents(arp_root, set_raw)
    if not any(f.elements for f in drawings.values()):return None
    empty = {'contract': 'diagram-coverage/1', 'counts': {}, 'covered': 0, 'coverage_percent': 0.0, 'design_counts': design_counts(Design(design or {}))}
    path = triage_path(workspace)
    if not path.is_file():return {**empty, 'status': 'FAIL', 'findings': [{'severity': 'FAIL', 'code': 'TRIAGE_MISSING'}]}
    triage = load(path.read_bytes())
    if (why := stale(workspace, triage, drawings)):return {**empty, 'status': 'FAIL', 'findings': [{'severity': 'FAIL', 'code': 'TRIAGE_STALE', 'reason': why}]}
    need = needs_reading(triage)
    reviews = []
    for document in need:
        part = part_of(workspace, document)
        if not part.first.is_file():continue
        raw = part.first.read_bytes()
        try:ledger = load_ledger(raw)
        except LedgerError:continue
        record = part.review(sha(raw))
        reviews.append((ledger, load_review(record.read_bytes()) if record.is_file() else None, sha(raw)))
    scoped = {d: drawings[d] for d in need}
    if reviews:report = coverage(combined([r[0] for r in reviews]), scoped, design or {}, asks=asks_state(workspace), reviews=reviews)
    else:
        out = Findings()
        for document in need:out.fail('DIAGRAM_NOT_LEDGERED', document, count=len(drawings[document].elements))
        report = {**empty, 'status': out.status, 'coverage_percent': 100.0 if not need else 0.0, 'findings': out.rows}
    for row in report['findings']:
        # The independent review belongs to the final mode.
        if row['code'] in ('REVIEW_MISSING', 'REVIEW_STALE'):row['severity'] = 'WARN'
    findings = Findings();findings.rows = report['findings']
    held = in_design(design or {})
    looks = {k.sha256: k for k in triage.looks}
    for doc in triage.documents:
        if doc.decision == 'PENDING':findings.warn('TRIAGE_PENDING', doc.document)
        for p in doc.pictures:
            look = looks.get(p.sha256) if p.sha256 else None
            if not look or look.kind not in DRAWS_SYSTEM or p.skipped == 'DUPLICATE':continue
            for service in look.services:
                keys = service_keys(service)
                if not keys:findings.warn('PICTURE_SERVICE_UNKNOWN', doc.document, p.ref, target=service)
                elif not keys & held:findings.warn('PICTURE_SERVICE_NOT_IN_DESIGN', doc.document, p.ref, target=service)
    counts = Counter(report.get('counts') or {})
    set_aside = [d for d in triage.documents if d.decision == 'NOT_ARCHITECTURE']
    counts['out_of_scope_documents'] += len(set_aside)
    counts['out_of_scope'] += sum(d.elements for d in set_aside)
    report.update(status=findings.status, counts=dict(counts), findings=findings.rows,
                  triage={'documents': len(triage.documents), 'architecture': sum(d.decision == 'ARCHITECTURE' for d in triage.documents),
                          'read': len(need), 'picture_only': sum(d.decision == 'ARCHITECTURE' and not d.readable for d in triage.documents),
                          'set_aside': len(set_aside), 'pending': sum(d.decision == 'PENDING' for d in triage.documents),
                          'looks': dict(sorted(Counter(k.kind for k in triage.looks).items()))})
    return report


def main(argv=None):
    """`aws-design diagram triage` and `look`; the diagram command hands these two subcommands here."""
    parser = argparse.ArgumentParser(prog='aws-design diagram')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('triage', help='decide which CURRENT documents draw the system and which pictures to look at (diagrams/triage.json)')
    p.add_argument('--workspace', required=True)
    p = sub.add_parser('look', help='record what one picture of the triage shows, by its SHA-256')
    p.add_argument('--workspace', required=True);p.add_argument('--image', required=True, help='the SHA-256 the triage lists')
    p.add_argument('--kind', required=True, choices=list(KINDS_JA));p.add_argument('--service', action='append', default=[], help='an AWS service the diagram shows')
    p.add_argument('--note', default='');p.add_argument('--actor', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'triage':
            result = build(args.workspace);result['pictures'] = pending(load(triage_path(args.workspace).read_bytes()))[:BATCH]
        else:result = record_look(args.workspace, args.image, args.kind, args.service, args.note, args.actor)
        sys.stdout.buffer.write((json.dumps(result, ensure_ascii=False) + '\n').encode('utf-8'));return 0
    except (InputError, OSError, ValueError) as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc)[:300] if isinstance(exc, (InputError, ValueError)) else type(exc).__name__}, ensure_ascii=False));return 2
