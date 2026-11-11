"""Diagram ledger: every drawing of the CURRENT documents, read once, and what the design makes of it.

ARP4 extracts each drawing (shape, picture, connector, group, graphic) with its text, alternative text, cell
anchor, group and recorded connector ends, and keeps images as assets. Its accepted structure may hold, per
visual, a graph read from an image, with the reading's method and actor. A worker agent writes a ledger that
gives every element of a document one disposition by its reference and never copies its text; an independent
checker reviews it. The design input maps elements by citing them in `sources` (`DOCUMENT_ID#s1-d4`), so a
reviewed ledger stays valid while the input changes. Coverage joins the two: every element has a target in
the input or an explicit disposition, a resource sits in the account, environment, region, zone, VPC and subnet
the frames around its icon say, and nothing the diagram draws apart is folded into one target without the
ledger saying so. Reports carry codes, references and counts, never the drawings' text.

References: `s1-d4` is the fourth drawing of the first sheet (or slide), `a3` the third image asset no drawing
shows, `v:ID/n:NODE` a node and `v:ID/e:2` the second edge of the graph of the accepted visual ID.
"""
import argparse
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, ValidationError, model_validator

from .models import StrictModel

REF = r'^(?:s[1-9][0-9]{0,3}-d[1-9][0-9]{0,5}|a[1-9][0-9]{0,5}|v:[^/#,\s]+/(?:n:[^/#,\s]+|e:[1-9][0-9]{0,5}))$'
Ref = Annotated[str, Field(pattern=REF)]
Hash = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
ID = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_-]{0,63}$')]
Disposition = Literal['RESOURCE', 'ACTOR', 'BOUNDARY', 'CONNECTION', 'ANNOTATION', 'LEGEND', 'DUPLICATE', 'OUT_OF_SCOPE',
                      'UNRESOLVED', 'EXPANDED', 'GROUP']
MAPPED = ('RESOURCE', 'ACTOR', 'BOUNDARY', 'CONNECTION')
# Boundaries the input holds as objects a citation names; regions and zones are values, the rest need no target.
CITED_BOUNDARIES = ('ACCOUNT', 'ENVIRONMENT', 'VPC', 'SUBNET')
REGION = r'^[a-z]{2}(?:-gov)?-[a-z]+-\d+$'
ZONE = r'^[a-z]{2}(?:-gov)?-[a-z]+-\d+[a-z]$|^[a-z]{3,4}\d-az\d+$'
GLOBAL = {'IAM', 'Organizations', 'CloudFront', 'Route53'}
VPC, SUBNET, SECURITY_GROUP = 'AWS::EC2::VPC', 'AWS::EC2::Subnet', 'AWS::EC2::SecurityGroup'
# A cluster whose instances sit in its subnets, and the resource that puts a gateway in a VPC.
CLUSTERS, ATTACHMENT = ('AWS::RDS::DBCluster', 'AWS::DocDB::DBCluster', 'AWS::Neptune::DBCluster'), 'AWS::EC2::VPCGatewayAttachment'
# Excel's default column width and row height in EMU, to place an anchor's offsets within its cells.
COLUMN_EMU, ROW_EMU, SLACK = 609600, 190500, 0.05


class InputError(ValueError):
    pass


class InputTooLarge(InputError):
    def __init__(self, size, limit):
        super().__init__(f'INPUT_TOO_LARGE: {size} bytes, over the limit of {limit}');self.size, self.limit = size, limit


class Author(StrictModel):
    actor: str = Field(min_length=1)
    model: str = ''


class Element(StrictModel):
    """What one element of a drawing is to the design. The reference names it; its text stays in ARP4."""
    ref: Ref
    disposition: Disposition
    # RESOURCE: the CloudFormation type or service the icon shows (AWS::Lambda::Function, Lambda).
    service: str = ''
    actor_kind: Literal['USER', 'OPERATOR', 'EXTERNAL_SYSTEM', 'AWS_SERVICE'] | None = None
    boundary: Literal['ACCOUNT', 'ENVIRONMENT', 'REGION', 'AZ', 'VPC', 'SUBNET', 'ON_PREMISES', 'OTHER'] | None = None
    # REGION and AZ boundaries: the region or zone code the frame names.
    value: str = ''
    purpose: str = ''
    # CONNECTION: the kind of line the legend gives it, the legend entry, and its ends when the original records none.
    line: Literal['PRIMARY', 'SECONDARY', 'FUTURE', 'OTHER'] | None = None
    legend: Ref | None = None
    ends: list[Ref] = Field(default_factory=list)
    # The frame holding it, when the anchors do not show it (an image's content, a frame drawn as lines).
    inside: Ref | None = None
    duplicate_of: Ref | None = None
    # vision: read by looking at the picture; `visual` names the ARP4 visual holding the image evidence.
    reading: Literal['parser', 'vision'] = 'parser'
    visual: str | None = None
    ask: ID | None = None
    reason: str = ''

    @model_validator(mode='after')
    def consistent(self):
        d = self.disposition
        if (d == 'RESOURCE') != bool(self.service.strip()) and not (d == 'ACTOR' and self.actor_kind == 'AWS_SERVICE'):
            raise ValueError('a RESOURCE names its service, and only a RESOURCE or an AWS_SERVICE actor has one')
        if (d == 'ACTOR') != (self.actor_kind is not None):raise ValueError('an ACTOR, and only an ACTOR, has actor_kind')
        if (d == 'BOUNDARY') != (self.boundary is not None):raise ValueError('a BOUNDARY, and only a BOUNDARY, has boundary')
        if self.boundary == 'REGION' and not re.match(REGION, self.value):raise ValueError('a REGION boundary gives its region code')
        if self.boundary == 'AZ' and not re.match(ZONE, self.value):raise ValueError('an AZ boundary gives its zone name or ID')
        if self.value and self.boundary not in ('REGION', 'AZ'):raise ValueError('only REGION and AZ boundaries have a value')
        if d != 'CONNECTION' and (self.line or self.legend or self.ends):raise ValueError('only a CONNECTION has line, legend and ends')
        if self.ends and len(self.ends) != 2:raise ValueError('a CONNECTION gives both ends or none')
        if (d == 'DUPLICATE') != (self.duplicate_of is not None) or self.duplicate_of == self.ref:
            raise ValueError('a DUPLICATE, and only a DUPLICATE, names another element it repeats')
        if d in ('UNRESOLVED', 'OUT_OF_SCOPE', 'DUPLICATE') and not self.reason.strip():raise ValueError(f'{d} needs a reason')
        if (d == 'UNRESOLVED') != (self.ask is not None):raise ValueError('an UNRESOLVED element, and only one, names the ask that settles it')
        if (self.reading == 'vision' or d == 'EXPANDED') and not self.visual:raise ValueError('a vision reading or EXPANDED image names its visual')
        return self


class LedgerDocument(StrictModel):
    document: str = Field(min_length=1)
    extraction_sha256: Hash
    # The accepted review of the document's ARP4 structure; needed when any element relies on a visual.
    structure_content_hash: Hash | None = None
    # Whether the document draws the system's architecture; one that does must contribute to the design.
    contains_architecture: bool
    reason: str = Field(min_length=1)
    # NOT_ARCHITECTURE: a document that draws nothing of the system (screenshots, operation screens, notes) is
    # disposed of as a whole, without an entry per element; both readings and the review must say so.
    scope: Literal['ELEMENTS', 'NOT_ARCHITECTURE'] = 'ELEMENTS'
    elements: list[Element] = Field(default_factory=list, max_length=20000)

    @model_validator(mode='after')
    def whole(self):
        if self.scope == 'NOT_ARCHITECTURE' and (self.contains_architecture or self.elements):
            raise ValueError('a NOT_ARCHITECTURE document draws no architecture and lists no elements')
        return self


class Ledger(StrictModel):
    contract: Literal['diagram-ledger/1']
    author: Author
    documents: list[LedgerDocument] = Field(min_length=1)


class LedgerReview(StrictModel):
    contract: Literal['diagram-review/1']
    ledger_sha256: Hash
    decision: Literal['accepted', 'rejected']
    actor: str = Field(min_length=1)
    author: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    recorded_at: str


class Adoption(StrictModel):
    """A reading taken out of use (RETIRE), or the independent reading made the one the design uses (ADOPT): which
    bytes, whose, where the retired file went, who decided and why. Nothing is overwritten or deleted."""
    contract: Literal['diagram-adoption/1']
    action: Literal['ADOPT', 'RETIRE']
    # The part's document; none for a workspace's single ledger.
    document: str | None = None
    adopted_sha256: Hash | None = None
    adopted_author: str | None = None
    retired_reading: Literal['ledger', 'reading-2'] | None = None
    retired_sha256: Hash | None = None
    # None when the retired file did not satisfy the contract.
    retired_author: str | None = None
    retired_to: str | None = None
    actor: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    recorded_at: str

    @model_validator(mode='after')
    def consistent(self):
        if (self.action == 'ADOPT') != (self.adopted_sha256 is not None):raise ValueError('an ADOPT, and only an ADOPT, names the adopted reading')
        if self.action == 'RETIRE' and self.retired_sha256 is None:raise ValueError('a RETIRE names the retired reading')
        if (self.retired_sha256 is None) != (self.retired_to is None):raise ValueError('a retired reading says where it went')
        return self


def sha(raw):return hashlib.sha256(raw).hexdigest()
def stamp(now=None):return (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
def dump(value):return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
def clean(text):return re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', str(text or ''))).strip()


class Drawings:
    """The drawings of one ARP4 document: elements by reference with their kind, texts, frame, group and line
    ends, the image assets no drawing shows, and the accepted structure's visuals and graphs."""

    def __init__(self, document_id, extraction_raw, mappings_raw=None, folder=None):
        import yaml
        self.document, self.folder, self.sha256 = document_id, folder, sha(extraction_raw)
        extraction = json.loads(extraction_raw)
        self.elements, ids, shown = {}, {}, set()
        for s, sheet in enumerate(extraction.get('sheets', []) or [], 1):
            for d, drawing in enumerate(sheet.get('drawings', []) or [], 1):
                ref = f's{s}-d{d}';ids[drawing.get('id')] = ref
                image = drawing.get('image') or {}
                if image.get('asset'):shown.add(image['asset'])
                self.elements[ref] = {'ref': ref, 'kind': drawing.get('kind', 'shape'), 'sheet': sheet.get('name', ''),
                                      'name': clean(drawing.get('name')), 'alt': clean(drawing.get('description')),
                                      'text': clean(drawing.get('text')), 'geometry': drawing.get('geometry'),
                                      'group': drawing.get('group'), 'rect': rect(drawing.get('anchor')), 'image': image.get('asset'),
                                      'head': drawing.get('head_end'), 'tail': drawing.get('tail_end'), 'dash': drawing.get('dash'),
                                      'connections': drawing.get('connections') or [], 'id': drawing.get('id'),
                                      'transform': drawing.get('transform') or {}}
        for a, asset in enumerate(extraction.get('assets', []) or [], 1):
            name = Path(str(asset.get('path', ''))).name
            if name in shown:continue
            ocr = asset.get('ocr') or {}
            self.elements[f'a{a}'] = {'ref': f'a{a}', 'kind': 'picture', 'sheet': '', 'name': name, 'alt': '',
                                      'text': clean(ocr.get('text')) if ocr.get('status') == 'available' else '', 'geometry': None,
                                      'group': None, 'rect': None, 'image': name, 'head': None, 'tail': None, 'dash': None,
                                      'connections': [], 'id': None}
        # Parents and line ends by the original's IDs; a connection target may be the bare shape number in its part.
        by_tail = {(i.split('#')[0], i.split('#')[-1]): r for i, r in ids.items() if isinstance(i, str)}
        def resolve(own, target):
            if target in ids:return ids[target]
            return by_tail.get(((own or '').split('#')[0], str(target).split('#')[-1]))
        for e in [e for e in self.elements.values() if e['id']]:
            e['group'] = resolve(e['id'], e['group']) if e['group'] else None
            ends = {c.get('end'): resolve(e['id'], c.get('target')) for c in e['connections'] if c.get('target')}
            e['ends'] = [ends.get('stCxn'), ends.get('endCxn')] if ends else []
        # A group's members share its anchor; their own offsets within the group place them inside it.
        for e in self.elements.values():
            if e.get('group') and e['rect']:e['rect'] = member_rect(e, self.elements)
        mappings = (yaml.safe_load(mappings_raw) or {}) if mappings_raw else {}
        interpretation = mappings.get('interpretation') or {}
        # Evidence paths are relative to the project holding .arp, however deep the document's folder sits.
        root = next((p.parent for p in folder.parents if p.name == '.arp'), None) if folder is not None else None
        self.regions = {str(r.get('id')): (root / r['image'] if root else Path(r['image'])) for r in interpretation.get('regions', []) or []
                        if isinstance(r, dict) and r.get('image')}
        review = interpretation.get('review') or {}
        self.structure_review = review.get('status', 'pending')
        self.structure_content_hash = review.get('content_hash') if review.get('status') == 'accepted' else None
        self.visuals = {}
        # Each correction record holds the visual beside the hashes of the drawings it reads.
        for record in interpretation.get('visuals', []) or []:
            visual = record.get('visual') or {}
            sources = [pointer_ref(p) for p in visual.get('sources', []) or []]
            self.visuals[str(visual.get('id'))] = {'kind': visual.get('kind'), 'state': visual.get('state'),
                                                   'evidence': visual.get('evidence') or [], 'sources': [r for r in sources if r],
                                                   'graph': visual.get('graph')}
            graph = visual.get('graph') or {}
            method = (graph.get('reading') or {}).get('method')
            for node in graph.get('nodes', []) or []:
                ref = f"v:{visual.get('id')}/n:{node.get('id')}"
                self.elements[ref] = {'ref': ref, 'kind': 'node', 'sheet': '', 'name': '', 'alt': '', 'text': clean(node.get('label')),
                                      'geometry': None, 'group': None, 'rect': None, 'image': None, 'head': None, 'tail': None,
                                      'dash': None, 'connections': [], 'id': None, 'visual': str(visual.get('id')), 'method': method}
            for n, edge in enumerate(graph.get('edges', []) or [], 1):
                ref = f"v:{visual.get('id')}/e:{n}"
                self.elements[ref] = {'ref': ref, 'kind': 'edge', 'sheet': '', 'name': '', 'alt': '', 'text': clean(edge.get('label')),
                                      'geometry': None, 'group': None, 'rect': None, 'image': None, 'head': None, 'tail': 'arrow',
                                      'dash': None, 'connections': [], 'id': None, 'visual': str(visual.get('id')), 'method': method,
                                      'ends': [f"v:{visual.get('id')}/n:{edge.get('from')}", f"v:{visual.get('id')}/n:{edge.get('to')}"]}
        for e in self.elements.values():e.setdefault('ends', [])
        self.frames = {}
        boxes = {r: e['rect'] for r, e in self.elements.items() if e['rect'] and e['kind'] not in ('connector',) and not is_line(e)}
        for ref, e in self.elements.items():
            # The frames around an element: its groups, then every larger drawing whose anchor encloses it or its group.
            chain, seen, at = [], set(), e
            while at.get('group') and at['group'] not in seen:seen.add(at['group']);chain.append(at['group']);at = self.elements[at['group']]
            own = e['rect'] or next((self.elements[g]['rect'] for g in chain if self.elements[g]['rect']), None)
            if own:
                # Anchors are cells of one sheet: a drawing of another sheet at the same cells is no frame.
                around = [r for r, box in boxes.items() if r != ref and r not in chain and page(r) == page(ref) and encloses(box, own)]
                chain += sorted(around, key=lambda r:area(boxes[r]))
            self.frames[ref] = chain

    def texts(self, ref):
        e = self.elements.get(ref)
        return [t for t in (e['text'], e['alt']) if t] if e else []

    def picture_path(self, ref):
        name = (self.elements.get(ref) or {}).get('image')
        if not name or not self.folder:return None
        for candidate in (self.folder / 'assets' / name, self.folder / name):
            if candidate.is_file():return candidate
        return None


def element_texts(extraction):
    """(reference, text) of the drawings and unshown image assets that hold text or alternative text; graph labels
    are a reading, not the document's words, and are left out."""
    shown = set()
    for s, sheet in enumerate(extraction.get('sheets', []) or [], 1):
        for d, drawing in enumerate(sheet.get('drawings', []) or [], 1):
            shown.add((drawing.get('image') or {}).get('asset'))
            text = ' '.join(t for t in (clean(drawing.get('text')), clean(drawing.get('description'))) if t)
            if text:yield f's{s}-d{d}', text
    for a, asset in enumerate(extraction.get('assets', []) or [], 1):
        ocr = asset.get('ocr') or {}
        if Path(str(asset.get('path', ''))).name not in shown and ocr.get('status') == 'available' and clean(ocr.get('text')):
            yield f'a{a}', clean(ocr.get('text'))


def page(ref):
    """The sheet or slide a reference lies on (`s3` of `s3-d4`), the visual of a graph element, or the reference itself."""
    if ref.startswith('v:'):return ref.split('/', 1)[0]
    return ref.split('-', 1)[0] if '-' in ref else ref


def is_line(e):return e.get('kind') == 'connector' or (e.get('geometry') or '').startswith(('line', 'straightConnector', 'bentConnector', 'curvedConnector'))


def rect(anchor):
    """(left, top, right, bottom) in cells, from a two-cell anchor; None when the anchor does not give both corners."""
    if not isinstance(anchor, dict):return None
    first, last = anchor.get('from') or {}, anchor.get('to') or {}
    if any(not isinstance(x.get(k), int) for x in (first, last) for k in ('col', 'row')):return None
    def at(corner):return (corner['col'] + (corner.get('colOff') or 0) / COLUMN_EMU, corner['row'] + (corner.get('rowOff') or 0) / ROW_EMU)
    (l, t), (r, b) = at(first), at(last)
    return (min(l, r), min(t, b), max(l, r), max(t, b))


def number(value):
    try:return float(value)
    except (TypeError, ValueError):return None


def member_rect(e, elements):
    """A group member's box: its offset and extent in the group's child space, scaled onto the group's box."""
    group = elements.get(e['group']) or {}
    outer, space, own = group.get('rect'), group.get('transform') or {}, e.get('transform') or {}
    origin, extent = space.get('chOff') or {}, space.get('chExt') or {}
    x, y = number((own.get('off') or {}).get('x')), number((own.get('off') or {}).get('y'))
    cx, cy = number((own.get('ext') or {}).get('cx')), number((own.get('ext') or {}).get('cy'))
    ox, oy, w, h = number(origin.get('x')) or 0, number(origin.get('y')) or 0, number(extent.get('cx')), number(extent.get('cy'))
    if not outer or None in (x, y, cx, cy) or not w or not h or not (cx or cy):return e['rect']
    left, top, right, bottom = outer
    sx, sy = (right - left) / w, (bottom - top) / h
    return (left + (x - ox) * sx, top + (y - oy) * sy, left + (x - ox + cx) * sx, top + (y - oy + cy) * sy)


def column(n):
    name = ''
    while n >= 0:name = chr(65 + n % 26) + name;n = n // 26 - 1
    return name


def cell(x, y):return f'{column(int(x))}{int(y) + 1}'


def line_points(e):
    """(start, end) of a line in cell coordinates: its box's corners, swapped by the flips the original records."""
    box, t = e.get('rect'), e.get('transform') or {}
    if not box:return None
    flip = lambda key:str(t.get(key, '')).lower() in ('1', 'true')
    (x1, x2), (y1, y2) = ((box[2], box[0]) if flip('flipH') else (box[0], box[2])), ((box[3], box[1]) if flip('flipV') else (box[1], box[3]))
    return (x1, y1), (x2, y2)


def near(found, point, own):
    """The smallest drawings whose box, widened by half a cell, holds a point: a guess at a line's unrecorded end."""
    x, y = point;found_at = []
    for ref, e in found.elements.items():
        box = e['rect']
        if ref == own or not box or is_line(e) or page(ref) != page(own):continue
        if box[0] - .5 <= x <= box[2] + .5 and box[1] - .5 <= y <= box[3] + .5:found_at.append((round(area(box), 3), ref))
    if not found_at:return []
    least = min(a for a, _ in found_at)
    return [r for a, r in found_at if a == least]


def area(box):return (box[2] - box[0]) * (box[3] - box[1])
def encloses(outer, inner):
    return (outer[0] - SLACK <= inner[0] and outer[1] - SLACK <= inner[1] and inner[2] <= outer[2] + SLACK and inner[3] <= outer[3] + SLACK
            and area(outer) > area(inner))


def pointer_ref(pointer):
    m = re.match(r'^/sheets/(\d+)/drawings/(\d+)$', str(pointer))
    if m:return f's{int(m.group(1)) + 1}-d{int(m.group(2)) + 1}'
    m = re.match(r'^/assets/(\d+)$', str(pointer))
    return f'a{int(m.group(1)) + 1}' if m else None


class Progress:
    """Progress of a long command as JSON lines on standard error, one per document read or checked, with the time
    spent and an estimate of the time left. Silent unless AWS_DESIGN_PROGRESS=jsonl or a command's --progress asks."""
    stream = None

    @classmethod
    def enabled(cls):
        import os
        return cls.stream is not None or os.environ.get('AWS_DESIGN_PROGRESS', '').lower() == 'jsonl'

    def __init__(self, step, total):
        import time
        self.step, self.total, self.done, self.start, self.on = step, total, 0, time.monotonic(), self.enabled()

    def tick(self, document, **more):
        if not self.on:return
        import time
        self.done += 1;elapsed = time.monotonic() - self.start
        line = {'progress': self.step, 'done': self.done, 'of': self.total, 'document': document, 'elapsed_s': round(elapsed, 1),
                'eta_s': round(elapsed / self.done * (self.total - self.done), 1), **more}
        stream = Progress.stream or sys.stderr
        stream.write(json.dumps(line, ensure_ascii=False) + '\n');stream.flush()


def read_documents(root, set_raw):
    """Drawings of each CURRENT document of the approved set, by document ID."""
    from .source_set import load_approved
    root = Path(root);base = root / '.arp' / 'documents'
    found = {}
    entries = [e for e in load_approved(set_raw).documents if e.status == 'CURRENT']
    progress = Progress('read', len(entries))
    for entry in entries:
        folder = base / entry.document_id
        if not (folder / 'extraction.json').is_file():progress.tick(entry.document_id, skipped=True);continue
        mappings = folder / 'mappings.yml'
        found[entry.document_id] = Drawings(entry.document_id, (folder / 'extraction.json').read_bytes(),
                                            mappings.read_bytes() if mappings.is_file() else None, folder)
        progress.tick(entry.document_id, elements=len(found[entry.document_id].elements))
    return found


# Bytes a ledger file may hold. A ledger lists every drawing of the CURRENT documents, so it grows with them;
# a review record is a few lines and keeps the guard every other handover has.
LEDGER_LIMIT, REVIEW_LIMIT = 64_000_000, 2_000_000


def read_json(raw, limit):
    """The one way a ledger or review file is read, by the diagram commands, the flow and the contract check alike:
    JSON within its byte limit, with no repeated key and no non-finite number."""
    if len(raw) > limit:raise InputTooLarge(len(raw), limit)
    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):raise InputError('NOT_JSON: a key is repeated')
        return dict(items)
    def constant(name):raise InputError(f'NOT_JSON: {name} is not a JSON number')
    try:return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=pairs, parse_constant=constant)
    except InputError:raise
    except (ValueError, UnicodeError):raise InputError('NOT_JSON: the file is not JSON') from None


def load(raw):
    data = read_json(raw, LEDGER_LIMIT)
    try:return Ledger.model_validate(data)
    except ValidationError as exc:
        raise InputError('CONTRACT_INVALID: ' + json.dumps(problems(exc)[:20], ensure_ascii=False)) from None


def load_review(raw):
    data = read_json(raw, REVIEW_LIMIT)
    try:return LedgerReview.model_validate(data)
    except ValidationError as exc:
        raise InputError('CONTRACT_INVALID: ' + json.dumps(problems(exc)[:20], ensure_ascii=False)) from None


def problems(exc):
    """Validation errors by location and type; the ledger's own rules add their message, which never holds a value."""
    return [{'loc': [str(x) for x in e['loc']], 'type': e['type'], **({'message': e['msg'].removeprefix('Value error, ')} if e['type'] == 'value_error' else {})}
            for e in exc.errors(include_input=False, include_context=False)]


class Findings:
    def __init__(self):self.rows = []
    def add(self, severity, code, document=None, ref=None, **more):
        self.rows.append({'severity': severity, 'code': code, **({'document': document} if document else {}),
                          **({'ref': ref} if ref else {}), **more})
    def fail(self, code, document=None, ref=None, **more):self.add('FAIL', code, document, ref, **more)
    def warn(self, code, document=None, ref=None, **more):self.add('WARN', code, document, ref, **more)
    @property
    def status(self):
        kinds = {r['severity'] for r in self.rows}
        return 'FAIL' if 'FAIL' in kinds else 'WARN' if 'WARN' in kinds else 'PASS'


# What in a drawing suggests it is part of the architecture: AWS and network words in its text, alternative text or name.
AWS_WORDS = re.compile(r'(?i)(?<![a-z])(aws|amazon|ec2|s3|rds|aurora|lambda|vpc|subnet|alb|elb|nlb|cloudfront|route ?53|dynamodb|ecs|eks|'
                       r'fargate|api gateway|sqs|sns|waf|direct connect|transit gateway|nat)(?![a-z])|サブネット|リージョン|アベイラビリティ')


def architecture_signs(found):
    """Counts of what in a document looks like architecture: lines that join two drawings, drawings that name AWS or
    network things, and graphs read from its images. None of them proves it; together they ask for a closer look."""
    joined = sum(1 for e in found.elements.values() if (e['kind'] == 'connector' or is_line(e)) and len(e['ends']) == 2 and all(e['ends']))
    named = sum(1 for e in found.elements.values() if AWS_WORDS.search(' '.join((e['text'], e['alt'], e['name']))))
    graphs = sum(1 for v in found.visuals.values() if v['graph'])
    return {k: v for k, v in (('joined_lines', joined), ('aws_named', named), ('graphs', graphs)) if v}


def check(ledger, drawings, part=None):
    """The ledger against the drawings alone: binding, one disposition per element, and readings that hold.
    `part` names the documents a part ledger reads; it must hold those and no others."""
    out = Findings()
    listed = Counter(d.document for d in ledger.documents)
    for document in [d for d, n in listed.items() if n > 1]:out.fail('DOCUMENT_LISTED_TWICE', document)
    if part is not None:drawings = {d: found for d, found in drawings.items() if d in part}
    for document, found in drawings.items():
        if found.elements and document not in listed:out.fail('DIAGRAM_NOT_LEDGERED', document, count=len(found.elements))
    progress = Progress('check', len(ledger.documents))
    for doc in ledger.documents:
        progress.tick(doc.document)
        if part is not None and doc.document not in part:out.fail('DOCUMENT_NOT_IN_PART', doc.document);continue
        found = drawings.get(doc.document)
        if found is None:out.fail('LEDGER_NOT_CURRENT', doc.document);continue
        if doc.extraction_sha256 != found.sha256:out.fail('LEDGER_STALE', doc.document);continue
        if doc.scope == 'NOT_ARCHITECTURE':
            # A document set aside as a whole: say what in it looks like architecture, for the review to weigh.
            signs = architecture_signs(found)
            if signs:out.warn('NOT_ARCHITECTURE_HAS_SIGNS', doc.document, **signs)
            continue
        refs = Counter(e.ref for e in doc.elements)
        for ref in [r for r, n in refs.items() if n > 1]:out.fail('ELEMENT_LISTED_TWICE', doc.document, ref)
        for ref in [r for r in refs if r not in found.elements]:out.fail('UNKNOWN_ELEMENT', doc.document, ref)
        for ref in [r for r in found.elements if r not in refs]:out.fail('ELEMENT_UNCLASSIFIED', doc.document, ref)
        by_ref = {e.ref: e for e in doc.elements}
        uses_structure = any(e.reading == 'vision' or e.visual or e.ref.startswith('v:') for e in doc.elements)
        if uses_structure:
            if found.structure_content_hash is None:out.fail('STRUCTURE_NOT_ACCEPTED', doc.document)
            elif doc.structure_content_hash != found.structure_content_hash:out.fail('STRUCTURE_STALE', doc.document)
        mapped = [e for e in doc.elements if e.disposition in MAPPED]
        if not doc.contains_architecture and mapped:out.fail('ARCHITECTURE_FLAG_CONTRADICTED', doc.document, mapped[0].ref)
        for e in doc.elements:
            source = found.elements.get(e.ref)
            if source is None:continue
            for name in ('inside', 'duplicate_of', 'legend'):
                target = getattr(e, name)
                if target and target not in found.elements:out.fail('UNKNOWN_ELEMENT', doc.document, e.ref, field=name)
            for end in e.ends:
                if end not in found.elements:out.fail('UNKNOWN_ELEMENT', doc.document, e.ref, field='ends')
            if e.duplicate_of and by_ref.get(e.duplicate_of) and by_ref[e.duplicate_of].disposition in ('DUPLICATE', 'OUT_OF_SCOPE'):
                out.fail('DUPLICATE_OF_UNMAPPED', doc.document, e.ref)
            if e.inside and by_ref.get(e.inside) and by_ref[e.inside].disposition != 'BOUNDARY':out.fail('INSIDE_NOT_A_BOUNDARY', doc.document, e.ref)
            if e.disposition == 'CONNECTION' and source['kind'] != 'edge' and not is_line(source) and not e.ends:
                out.fail('CONNECTION_NOT_A_LINE', doc.document, e.ref)
            # A line's ends come from the original's recorded connections, else the ledger gives them.
            if e.disposition == 'CONNECTION' and not e.ends and not (len(source['ends']) == 2 and all(source['ends'])):
                out.fail('CONNECTION_ENDS_UNKNOWN', doc.document, e.ref)
            if e.visual:
                visual = found.visuals.get(e.visual)
                if visual is None:out.fail('UNKNOWN_VISUAL', doc.document, e.ref)
                elif e.reading == 'vision' and (visual['state'] != 'read' or not visual['evidence']):out.fail('VISION_WITHOUT_EVIDENCE', doc.document, e.ref)
                elif e.disposition == 'EXPANDED' and (not visual['graph'] or e.ref not in visual['sources']):
                    out.fail('EXPANDED_WITHOUT_GRAPH', doc.document, e.ref)
            if e.disposition == 'EXPANDED' and source['kind'] != 'picture':out.fail('EXPANDED_NOT_A_PICTURE', doc.document, e.ref)
            if e.disposition == 'GROUP' and source['kind'] != 'group':out.fail('GROUP_NOT_A_GROUP', doc.document, e.ref)
            # An image is read by its alternative text or by looking at it; its file name says nothing.
            if (source['kind'] == 'picture' and e.disposition in MAPPED and e.reading == 'parser' and not source['alt'] and not source['text']):
                out.fail('PICTURE_NOT_READ', doc.document, e.ref)
            if source['kind'] == 'picture' and e.disposition in ('ANNOTATION', 'LEGEND') and not source['alt'] and e.reading == 'parser':
                out.warn('PICTURE_NOT_READ', doc.document, e.ref)
        # A picture whose visual holds a graph is read through it: the picture must say so.
        for visual_id, visual in found.visuals.items():
            if not visual['graph']:continue
            for ref in visual['sources']:
                e = by_ref.get(ref)
                if e and found.elements.get(ref, {}).get('kind') == 'picture' and e.disposition != 'EXPANDED':
                    out.warn('GRAPH_NOT_EXPANDED', doc.document, ref, visual=visual_id)
    return out


# Failures that say a ledger does not belong to the document or the source set it is checked against: a wrong
# input, not a wrong reading.
NOT_THIS_DOCUMENT = ('LEDGER_NOT_CURRENT', 'DOCUMENT_NOT_IN_PART', 'DIAGRAM_NOT_LEDGERED', 'DOCUMENT_LISTED_TWICE')


def citations(design):
    """(document, element reference) → [(kind, object ID)] for every object whose sources cite drawing elements."""
    locators = {s.get('id'): str(s.get('locator', '')) for s in design.get('sources', []) or [] if isinstance(s, dict)}
    found = defaultdict(list)
    groups = [('resource', design.get('resources')), ('actor', design.get('actors')), ('connection', design.get('connections')),
              ('account', design.get('accounts')), ('environment', design.get('environments'))]
    for kind, objects in groups:
        for obj in objects or []:
            if not isinstance(obj, dict):continue
            for source in obj.get('sources', []) or []:
                document, _, place = locators.get(source, '').partition('#')
                for part in place.split(','):
                    if re.match(REF, part.strip()):found[document, part.strip()].append((kind, obj.get('id')))
    return found


def refs_of(resource):
    """Resource IDs a resource's own settings and environment overrides name through RESOURCE_REF."""
    found = []
    def walk(setting):
        if not isinstance(setting, dict) or setting.get('status', 'DECIDED') != 'DECIDED':return
        if setting.get('mode') == 'RESOURCE_REF':
            ref = setting.get('ref');found.extend(ref if isinstance(ref, list) else [ref])
        elif setting.get('mode') == 'COMPOSITE':
            def inner(value):
                if isinstance(value, dict):
                    if set(value) == {'$design'}:walk(value['$design']);return
                    for v in value.values():inner(v)
                elif isinstance(value, list):
                    for v in value:inner(v)
            inner(setting.get('value'))
    for setting in (resource.get('settings') or {}).values():walk(setting)
    for override in resource.get('_overrides', []):
        for setting in (override.get('settings') or {}).values():walk(setting)
    return found


class Design:
    """The parts of a design input the coverage reads, as plain lookups."""

    def __init__(self, design):
        self.environments = {e['id']: e for e in design.get('environments', []) or [] if isinstance(e, dict) and 'id' in e}
        self.resources = {r['id']: dict(r) for r in design.get('resources', []) or [] if isinstance(r, dict) and 'id' in r}
        for env in self.environments.values():
            for o in env.get('overrides', []) or []:
                if o.get('resource_id') in self.resources:self.resources[o['resource_id']].setdefault('_overrides', []).append(o)
        self.actors = {a['id']: a for a in design.get('actors', []) or [] if isinstance(a, dict) and 'id' in a}
        self.accounts = {a['id']: a for a in design.get('accounts', []) or [] if isinstance(a, dict) and 'id' in a}
        self.connections = {c['id']: c for c in design.get('connections', []) or [] if isinstance(c, dict) and 'id' in c}
        self.refs = {rid: refs_of(r) for rid, r in self.resources.items()}

    def present(self, rid):
        named = self.resources[rid].get('environments') or []
        return [e for e in self.environments if not named or e in named]

    def account(self, rid, env):
        own = self.resources[rid].get('account') if rid in self.resources else (self.actors.get(rid) or {}).get('account')
        return own or self.environments[env].get('account')

    def region(self, rid, env):
        own = self.resources[rid].get('region') if rid in self.resources else (self.actors.get(rid) or {}).get('region')
        return own or self.environments[env].get('region')

    def type(self, rid):return (self.resources.get(rid) or {}).get('type', '')

    def literal(self, rid, name):
        setting = (self.resources.get(rid, {}).get('settings') or {}).get(name)
        if isinstance(setting, dict) and setting.get('status', 'DECIDED') == 'DECIDED' and setting.get('mode') == 'LITERAL':return setting.get('value')
        return None

    def subnets(self, rid, seen=()):
        """Subnets a resource names directly, through a subnet group, or through the cluster it is an instance of."""
        found = set()
        for x in self.refs.get(rid, []):
            if self.type(x) == SUBNET:found.add(x)
            elif self.type(x).endswith('SubnetGroup'):found.update(y for y in self.refs.get(x, []) if self.type(y) == SUBNET)
            elif self.type(x) in CLUSTERS and x not in seen:found |= self.subnets(x, (*seen, rid))
        return {rid} if self.type(rid) == SUBNET else found

    def vpcs(self, rid):
        """VPCs a resource names, directly or through its subnets and security groups; a gateway's VPC is the one
        its attachment names, since the gateway itself names none."""
        found = set()
        attached = [y for a, refs in self.refs.items() if self.type(a) == ATTACHMENT and rid in refs for y in refs]
        for x in self.refs.get(rid, []) + sorted(self.subnets(rid)) + attached:
            if self.type(x) == VPC:found.add(x)
            elif self.type(x) in (SUBNET, SECURITY_GROUP):found.update(y for y in self.refs.get(x, []) if self.type(y) == VPC)
        return {rid} if self.type(rid) == VPC else found


def service_matches(named, kind):
    """A ledger's service against a resource type: the same namespace, or a service name the dictionary knows whose
    types hold it (`EventBridge Scheduler` and AWS::Scheduler::ScheduleGroup, `Aurora` and AWS::RDS::DBInstance)."""
    if '::' not in kind:return False
    if service_key(named) == service_key(kind):return True
    from .service_mentions import detect, type_holds
    return not named.strip().startswith('AWS::') and any(type_holds(key, kind) for key in detect(named))


def judge_review(out, ledger, review, ledger_sha256, documents=None):
    """One reading's independent review: present, of these exact bytes, accepted and by someone else."""
    where = {'documents': documents[:20]} if documents else {}
    if review is None:out.fail('REVIEW_MISSING', **where)
    elif review.ledger_sha256 != ledger_sha256:out.fail('REVIEW_STALE', **where)
    elif review.decision != 'accepted':out.fail('REVIEW_REJECTED', **where)
    elif review.actor.strip() == ledger.author.actor.strip():out.fail('REVIEWER_IS_AUTHOR', **where)


def combined(ledgers):
    """The part ledgers read as one, for the coverage: their documents together."""
    if len(ledgers) == 1:return ledgers[0]
    return Ledger.model_construct(contract='diagram-ledger/1', author=ledgers[0].author,
                                  documents=[d for ledger in ledgers for d in ledger.documents])


def coverage(ledger, drawings, design, *, asks=None, review=None, ledger_sha256=None, reviews=None):
    """The ledger joined with the design input: findings, counts per disposition and the coverage. With part
    ledgers, `ledger` is them together and `reviews` holds (ledger, review, sha256) for each part."""
    out = check(ledger, drawings)
    asks = asks or {}
    model = Design(design);cited = citations(design)
    for part, part_review, digest in reviews if reviews is not None else [(ledger, review, ledger_sha256)]:
        judge_review(out, part, part_review, digest, [d.document for d in part.documents] if reviews is not None else None)
    counts = Counter();covered = 0;total = 0
    by_object = defaultdict(list);read = {}
    for doc in ledger.documents:
        found = drawings.get(doc.document)
        if found is None or doc.extraction_sha256 != found.sha256:continue
        by_ref = {e.ref: e for e in doc.elements};read[doc.document] = (doc, found, by_ref)
        if doc.scope == 'NOT_ARCHITECTURE':
            total += len(found.elements);covered += len(found.elements)
            counts['out_of_scope'] += len(found.elements);counts['out_of_scope_documents'] += 1
            for ref in sorted(r for d, r in cited if d == doc.document):out.fail('CITES_OUT_OF_SCOPE_DOCUMENT', doc.document, ref)
            continue
        contributed = 0
        for e in doc.elements:
            if e.ref not in found.elements:continue
            total += 1;targets = cited.get((doc.document, e.ref), [])
            counts[{'RESOURCE': 'mapped_resources', 'ACTOR': 'mapped_actors', 'BOUNDARY': 'mapped_boundaries',
                    'CONNECTION': 'mapped_connections', 'ANNOTATION': 'legends_and_annotations', 'LEGEND': 'legends_and_annotations',
                    'DUPLICATE': 'duplicates', 'OUT_OF_SCOPE': 'out_of_scope', 'UNRESOLVED': 'unresolved',
                    'EXPANDED': 'expanded_images', 'GROUP': 'groups'}[e.disposition]] += 1
            ok = judge(out, doc, e, targets, by_ref, model, cited, asks)
            if targets:contributed += 1
            covered += ok
            # Another document may draw the same resource again; within one document a repeat is a DUPLICATE.
            if e.disposition in ('RESOURCE', 'ACTOR'):
                for kind, oid in targets:by_object[doc.document, kind, oid].append((doc.document, e))
        for ref in [r for r in found.elements if r not in by_ref]:total += 1
        if doc.contains_architecture and not contributed:out.fail('NO_CONTRIBUTION', doc.document)
        placements(out, doc, found, by_ref, model, cited)
        lines(out, doc, found, by_ref, model, cited)
    for (_, kind, oid), elements in by_object.items():
        # One input object for several elements the diagram draws apart folds them together.
        apart = [(d, e) for d, e in elements if e.disposition != 'DUPLICATE']
        if len(apart) > 1:
            services = {service_key(e.service) for _, e in apart if e.service.strip()}
            if len(services) <= 1 and kind == 'resource' and spans_zones(model, oid, [zone_of(*read[d], e.ref, cited) for d, e in apart]):continue
            out.fail('AGGREGATED_SERVICES' if len(services) > 1 else 'AGGREGATED_ELEMENTS', target=oid,
                     refs=[f'{d}#{e.ref}' for d, e in apart][:20])
    for (document, ref), targets in cited.items():
        if document in drawings and ref in drawings[document].elements:
            doc = next((d for d in ledger.documents if d.document == document), None)
            if doc is None:out.fail('CITES_UNLEDGERED_ELEMENT', document, ref)
    counts['source_elements'] = total
    rate = round(100 * covered / total, 1) if total else 100.0
    return {'contract': 'diagram-coverage/1', 'status': out.status, 'counts': dict(counts), 'covered': covered, 'coverage_percent': rate,
            'design_counts': design_counts(model), 'findings': out.rows}


def judge(out, doc, e, targets, by_ref, model, cited, asks):
    """Whether one element is covered: it has a target of the right kind, or an explicit disposition that needs none."""
    d, document = e.disposition, doc.document
    kinds = {k for k, _ in targets}
    if d not in MAPPED and d != 'DUPLICATE' and targets:
        out.fail('CITES_UNMAPPED_ELEMENT', document, e.ref, targets=[o for _, o in targets]);return False
    if d == 'DUPLICATE':
        original = cited.get((document, e.duplicate_of), [])
        if targets and set(targets) - set(original):out.fail('DUPLICATE_CITED_APART', document, e.ref);return False
        return True
    if d == 'UNRESOLVED':
        state = asks.get(e.ask, 'MISSING')
        if state == 'ANSWERED':out.fail('UNRESOLVED_ANSWERED', document, e.ref, ask=e.ask);return False
        out.warn({'HELD': 'UNRESOLVED_HELD', 'OPEN': 'UNRESOLVED_PENDING', 'MISSING': 'ASK_NOT_DRAFTED'}[state], document, e.ref, ask=e.ask)
        return state == 'HELD'
    if d not in MAPPED:return True
    allowed = {'RESOURCE': {'resource', 'actor'}, 'ACTOR': {'actor'}, 'CONNECTION': {'connection'},
               'BOUNDARY': {'ACCOUNT': {'account'}, 'ENVIRONMENT': {'environment'}, 'VPC': {'resource'}, 'SUBNET': {'resource'}}.get(e.boundary, {'actor'})}[d]
    if kinds - allowed:out.fail('KIND_MISMATCH', document, e.ref, targets=[o for _, o in targets]);return False
    required = d != 'BOUNDARY' or e.boundary in CITED_BOUNDARIES
    if not targets:
        if required:out.fail('TARGET_MISSING', document, e.ref, disposition=d);return False
        return True
    for kind, oid in targets:
        if d == 'RESOURCE' and kind == 'resource' and not service_matches(e.service, model.type(oid)):
            out.warn('SERVICE_MISMATCH', document, e.ref, target=oid)
        if d == 'RESOURCE' and kind == 'actor':
            actor = model.actors.get(oid) or {}
            if actor.get('kind') != 'AWS_SERVICE':out.fail('KIND_MISMATCH', document, e.ref, targets=[oid]);return False
        if d == 'BOUNDARY' and e.boundary in ('VPC', 'SUBNET') and model.type(oid) != {'VPC': VPC, 'SUBNET': SUBNET}[e.boundary]:
            out.fail('KIND_MISMATCH', document, e.ref, targets=[oid]);return False
    return True


def boundaries(doc, found, by_ref, ref):
    """The boundary elements around an element, innermost first: its declared frame and that frame's, else the anchors'."""
    chain, seen, at = [], set(), ref
    while at and at not in seen:
        seen.add(at);e = by_ref.get(at)
        if e and e.inside:
            frame = by_ref.get(e.inside)
            if frame and frame.disposition == 'BOUNDARY':chain.append(frame)
            at = e.inside;continue
        for r in found.frames.get(at, []):
            frame = by_ref.get(r)
            if frame and frame.disposition == 'BOUNDARY' and frame not in chain:chain.append(frame)
        break
    return chain


def zone_of(doc, found, by_ref, ref, cited):
    """Where an element is drawn apart from other drawings of its resource: the innermost subnet frame the input
    maps, else the innermost zone frame."""
    for frame in boundaries(doc, found, by_ref, ref):
        if frame.boundary == 'SUBNET':
            subnet = next((oid for k, oid in cited.get((doc.document, frame.ref), []) if k == 'resource'), None)
            if subnet:return ('SUBNET', subnet)
        elif frame.boundary == 'AZ' and frame.value:return ('AZ', frame.value)
    return None


def spans_zones(model, oid, places):
    """One resource drawn once per subnet or zone it spans (an ECS service, an Auto Scaling group): every drawing
    sits in its own subnet or zone frame, and the resource's subnets hold each of them."""
    if None in places or len(set(places)) != len(places):return False
    subnets = model.subnets(oid)
    zones = {model.literal(s, 'AvailabilityZone') or model.literal(s, 'AvailabilityZoneId') for s in subnets} - {None}
    return all((value in subnets) if kind == 'SUBNET' else (value in zones) for kind, value in places)


def placements(out, doc, found, by_ref, model, cited):
    """Each resource where the frames around its icon put it: account, environment, region, zone, VPC and subnet."""
    def target(frame, kind):
        return next((oid for k, oid in cited.get((doc.document, frame.ref), []) if k == kind), None)
    for e in [x for x in by_ref.values() if x.disposition in ('RESOURCE', 'ACTOR')]:
        frames = boundaries(doc, found, by_ref, e.ref)
        if not frames:continue
        for kind, oid in cited.get((doc.document, e.ref), []):
            if kind == 'actor' and (model.actors.get(oid) or {}).get('kind') != 'AWS_SERVICE':continue
            if kind not in ('resource', 'actor'):continue
            envs = model.present(oid) if kind == 'resource' else list(model.environments)
            where = next((target(f, 'environment') for f in frames if f.boundary == 'ENVIRONMENT' and target(f, 'environment')), None)
            if where:
                if where not in envs:out.fail('PLACEMENT_MISMATCH', doc.document, e.ref, target=oid, boundary='ENVIRONMENT', expected=where);continue
                envs = [where]
            for frame in frames:
                if frame.boundary == 'ACCOUNT' and target(frame, 'account'):
                    wanted = target(frame, 'account');actual = {model.account(oid, env) for env in envs}
                    if None in actual:out.fail('PLACEMENT_NOT_DECLARED', doc.document, e.ref, target=oid, boundary='ACCOUNT', expected=wanted)
                    elif actual != {wanted}:out.fail('PLACEMENT_MISMATCH', doc.document, e.ref, target=oid, boundary='ACCOUNT', expected=wanted, actual=sorted(actual))
                elif frame.boundary == 'REGION':
                    if kind == 'resource' and model.type(oid).split('::')[1:2] and model.type(oid).split('::')[1] in GLOBAL:continue
                    actual = {model.region(oid, env) for env in envs}
                    if actual != {frame.value}:out.fail('PLACEMENT_MISMATCH', doc.document, e.ref, target=oid, boundary='REGION', expected=frame.value, actual=sorted(actual))
                elif kind == 'resource' and frame.boundary == 'AZ':
                    # The resource's own zone when it states one (a database instance), else the zones of its subnets;
                    # subnets whose zone is still open cannot refute the drawing.
                    own = model.literal(oid, 'AvailabilityZone')
                    known = [model.literal(s, 'AvailabilityZone') or model.literal(s, 'AvailabilityZoneId') for s in model.subnets(oid)]
                    zones = {own} if own else set(known) - {None}
                    if not zones or (frame.value not in zones and not own and None in known):
                        out.warn('PLACEMENT_UNVERIFIED', doc.document, e.ref, target=oid, boundary='AZ')
                    elif frame.value not in zones:out.fail('PLACEMENT_MISMATCH', doc.document, e.ref, target=oid, boundary='AZ', expected=frame.value, actual=sorted(zones))
                elif kind == 'resource' and frame.boundary in ('VPC', 'SUBNET') and target(frame, 'resource'):
                    wanted = target(frame, 'resource')
                    if wanted == oid:continue
                    actual = model.vpcs(oid) if frame.boundary == 'VPC' else model.subnets(oid)
                    if not actual:out.warn('PLACEMENT_UNVERIFIED', doc.document, e.ref, target=oid, boundary=frame.boundary)
                    elif wanted not in actual:out.fail('PLACEMENT_MISMATCH', doc.document, e.ref, target=oid, boundary=frame.boundary, expected=wanted, actual=sorted(actual))


def lines(out, doc, found, by_ref, model, cited):
    """Each line's input connection joins what its two ends are in the input; the arrow's direction is compared."""
    for e in [x for x in by_ref.values() if x.disposition == 'CONNECTION']:
        source = found.elements.get(e.ref) or {}
        ends = e.ends or source.get('ends') or []
        if len(ends) != 2 or not all(ends):continue
        def objects(ref, seen=()):
            # A line ending on a duplicate icon ends where the original's target is; one ending on a group, at its members'.
            el = by_ref.get(ref)
            if el and el.disposition == 'GROUP' and ref not in seen:
                members = [r for r, m in found.elements.items() if m.get('group') == ref]
                return set().union(*(objects(r, (*seen, ref)) for r in members)) if members else set()
            ref = el.duplicate_of if el and el.disposition == 'DUPLICATE' else ref
            return {oid for k, oid in cited.get((doc.document, ref), []) if k in ('resource', 'actor')}
        first, last = objects(ends[0]), objects(ends[1])
        if not first or not last:out.warn('LINE_END_UNMAPPED', doc.document, e.ref);continue
        for kind, cid in cited.get((doc.document, e.ref), []):
            c = model.connections.get(cid) or {}
            pair = (c.get('source'), c.get('target'))
            if pair[0] in first and pair[1] in last:continue
            if pair[0] in last and pair[1] in first:
                # Reversed against the drawn order: only an arrowhead at the end alone says the line points the other way.
                if source.get('tail') and not source.get('head'):out.warn('DIRECTION_DIFFERS', doc.document, e.ref, target=cid)
                continue
            out.fail('CONNECTION_ENDS_MISMATCH', doc.document, e.ref, target=cid)


def design_counts(model):
    """Service types, logical resources and placements (a resource in each environment it exists in), by account,
    environment, region and decided zone."""
    services = {r.get('type', '').split('::')[1] for r in model.resources.values() if '::' in r.get('type', '')}
    services |= {a.get('service', '').strip() for a in model.actors.values() if a.get('kind') == 'AWS_SERVICE' and a.get('service')}
    by = {'account': Counter(), 'environment': Counter(), 'region': Counter(), 'availability_zone': Counter()}
    placements = 0
    for rid in model.resources:
        zones = sorted({model.literal(s, 'AvailabilityZone') or model.literal(s, 'AvailabilityZoneId') for s in model.subnets(rid)} - {None})
        for env in model.present(rid):
            placements += 1
            by['account'][model.account(rid, env) or '未決定'] += 1;by['environment'][env] += 1
            by['region'][model.region(rid, env) or '未決定'] += 1
            for zone in zones or ['未決定']:by['availability_zone'][zone] += 1
    aws_actors = [a for a in model.actors.values() if a.get('kind') == 'AWS_SERVICE']
    return {'service_types': len(services), 'logical_resources': len(model.resources) + len(aws_actors), 'placements': placements,
            'placements_by': {k: dict(sorted(v.items())) for k, v in by.items()}}


LABELS = [('source_elements', 'Source elements'), ('mapped_resources', 'Mapped resources'), ('mapped_actors', 'Mapped actors'),
          ('mapped_boundaries', 'Mapped boundaries'), ('mapped_connections', 'Mapped connections'),
          ('legends_and_annotations', 'Legends and annotations'), ('duplicates', 'Duplicates'), ('groups', 'Groups'),
          ('expanded_images', 'Expanded images'),
          ('out_of_scope', 'Out of scope'), ('out_of_scope_documents', 'Documents set aside as a whole'), ('unresolved', 'Unresolved')]


def render(report):
    counts = report['counts'];design = report['design_counts']
    lines_ = ['# 構成図の対比カバレッジ', '', '```text', *[f'{label}: {counts.get(key, 0)}' for key, label in LABELS],
              f"Coverage: {report['coverage_percent']}%", f"Result: {report['status']}", '```', '',
              'カバレッジは、すべての要素に入力での対応先か明示的な処置がある割合です。すべてをAWSリソースにした割合ではありません。', '',
              '## 設計入力の数', '', '| 数え方 | 件数 |', '| --- | --- |', f"| AWSサービス種類数 | {design['service_types']} |",
              f"| 論理リソース数 | {design['logical_resources']} |", f"| 配置実体数（リソース×存在する環境） | {design['placements']} |", '']
    for key, title in (('account', 'アカウント別'), ('environment', '環境別'), ('region', 'リージョン別'), ('availability_zone', 'AZ別')):
        rows = design['placements_by'][key]
        if rows:lines_ += [f'### 配置実体数（{title}）', '', '| 区分 | 件数 |', '| --- | --- |', *[f'| {k} | {v} |' for k, v in rows.items()], '']
    if report.get('triage'):
        t = report['triage']
        lines_ += ['## 画像の仕分け（下書きモード）', '', f"図形・画像のある文書 {t['documents']}件：構成を描く見込み {t['architecture']}件"
                   f"（要素ごとに読んだ文書 {t['read']}件、画像だけの文書 {t['picture_only']}件）、描かない見込み {t['set_aside']}件、"
                   f"画像を見る前 {t['pending']}件。見た画像：" + ('、'.join(f'{k} {v}' for k, v in t['looks'].items()) or 'なし') + '。', '']
    lines_ += ['## 指摘', '']
    if not report['findings']:lines_.append('なし')
    for f in report['findings']:
        where = '#'.join(x for x in (f.get('document'), f.get('ref')) if x)
        extra = '、'.join(f'{k}={v}' for k, v in f.items() if k not in ('severity', 'code', 'document', 'ref'))
        lines_.append(f"- {f['severity']} `{f['code']}` {where} {extra}".rstrip())
    fixes = [(code, text) for code, text in FIXES if any(f['code'] == code for f in report['findings'])]
    if fixes:lines_ += ['', '## 指摘の直し方', '', *[f'- `{code}`：{text}' for code, text in fixes]]
    return '\n'.join(lines_) + '\n'


# How an author answers the warnings a weaker agent otherwise leaves or guesses at; shown under the findings they are about.
FIXES = (
    ('PICTURE_NOT_READ', '文字も代替テキストもない画像で、中身を誰も見ていない。下書きでは `aws-design diagram look` で画像を見て種類を記録する。'
     '構成を描かない画像（ロゴ、写真、画面、表）と記録すれば、この警告は次の生成で消える。構成を描く画像なら、描かれたサービスを記録し、入力にあるかを確かめる。'),
    ('KIND_MISMATCH', '図形の処置と、その図形を引用する入力のもの（targets）の種類が合わない。RESOURCE の図形を引用できるのはリソースと AWS_SERVICE のアクター、'
     'ACTOR はアクター、CONNECTION は接続。枠（BOUNDARY）は、ACCOUNT ならアカウント、ENVIRONMENT なら環境、VPC・SUBNET ならその型のリソースが引用する。'
     'REGION・AZ・ON_PREMISES・OTHER の枠は、リソースからは引用しない：その引用を入力の `sources` から外す'
     '（リージョンは環境かリソースの `region`、AZ はサブネットの `AvailabilityZone` で表し、その設定が枠を引用するのはよい）。'
     '台帳の読み違い（アクターを RESOURCE にした、など）なら台帳を直す。'),
    ('PLACEMENT_UNVERIFIED', '図は target を枠（boundary）の中に描いているが、入力に target からその VPC・サブネット・AZ へたどれる参照がない。'
     '文書が配置を決めているなら、入力に参照を書く。サブネットを取る設定（`SubnetIds`、`SubnetId`、`DBSubnetGroupName` など）を、サブネットかサブネットグループへの RESOURCE_REF にする。'
     'Aurora のインスタンスは `DBClusterIdentifier` をクラスターへの RESOURCE_REF にし、クラスターの `DBSubnetGroupName` をサブネットグループへの RESOURCE_REF にする。'
     'インターネットゲートウェイは、`InternetGatewayId` と `VpcId` を RESOURCE_REF にした `AWS::EC2::VPCGatewayAttachment` を入力に足す。'
     'AZ は、参照先のサブネットの `AvailabilityZone` が決まっていれば確かめられる。文書が配置を決めていないなら、警告のままでよい（下書きは止まらない）。'),
    ('SERVICE_MISMATCH', '台帳の `service` と、その図形を引用する入力のリソース（target）の型で、サービスが違う。台帳の読み違いなら台帳の `service` を直し、'
     '入力が別の図形を引用しているなら入力の `sources` を直す。'),
    ('LINE_END_UNMAPPED', '線の端の図形に、入力での対応先がない。端の図形を引用するリソースかアクターが入力にあるかを見る。注記への線なら、台帳でその線を ANNOTATION にする。'),
)


# What a disagreement is about, most important first. Whether an element is there, what it is, where it sits and
# what a line joins change the design (MAJOR); how a drawing that maps to nothing is filed does not (MINOR).
CLASSES = ('SCOPE', 'MISSING', 'RESOURCE', 'PLACEMENT', 'CONNECTION', 'ACTOR', 'NOTATION')
MAJOR = ('SCOPE', 'MISSING', 'RESOURCE', 'PLACEMENT', 'CONNECTION', 'ACTOR')
FIELD_CLASS = {'service': 'RESOURCE', 'boundary': 'PLACEMENT', 'value': 'PLACEMENT', 'inside': 'PLACEMENT',
               'ends': 'CONNECTION', 'line': 'CONNECTION', 'actor_kind': 'ACTOR', 'duplicate_of': 'NOTATION'}
DISPOSITION_CLASS = {'RESOURCE': 'RESOURCE', 'BOUNDARY': 'PLACEMENT', 'CONNECTION': 'CONNECTION', 'ACTOR': 'ACTOR'}


def classes_of(x, y, differ):
    found = {FIELD_CLASS[f] for f in differ if f in FIELD_CLASS}
    if 'disposition' in differ:
        found |= {DISPOSITION_CLASS[d] for d in (x.disposition, y.disposition) if d in DISPOSITION_CLASS} or {'NOTATION'}
    return [c for c in CLASSES if c in found]


def compare(first, second):
    """Elements two independent ledgers read differently, by reference and field, each classed by what it is about
    and how much it matters, with the agreement per document; no text. Equivalent service names are one service."""
    if first.author.actor.strip() == second.author.actor.strip():raise InputError('SAME_AUTHOR: compare two independent readings')
    fields = ('disposition', 'service', 'actor_kind', 'boundary', 'value', 'duplicate_of', 'inside', 'ends', 'line')
    # A document either reading sets aside as a whole is compared as a whole: one SCOPE disagreement, not one per element.
    scopes = [{d.document: d.scope for d in ledger.documents} for ledger in (first, second)]
    whole = {d for s in scopes for d, scope in s.items() if scope == 'NOT_ARCHITECTURE'}
    def index(ledger):
        found = {(d.document, e.ref): e for d in ledger.documents if d.document not in whole for e in d.elements}
        return found | {(d.document, ''): d for d in ledger.documents if d.document in whole}
    a, b = index(first), index(second);rows = []
    for key in sorted(set(a) | set(b)):
        x, y = a.get(key), b.get(key)
        if key[1] == '':
            if x is None or y is None or x.scope != y.scope:
                rows.append({'document': key[0], 'ref': '', 'fields': ['scope'], 'code': 'SCOPE', 'classes': ['SCOPE'], 'severity': 'MAJOR'})
            continue
        if x is None or y is None:
            differ, classes = ['missing'], ['MISSING']
        else:
            differ = [f for f in fields if (getattr(x, f) or None) != (getattr(y, f) or None) and not (f == 'service' and service_same(x.service, y.service))]
            classes = classes_of(x, y, differ)
        if differ:rows.append({'document': key[0], 'ref': key[1], 'fields': differ, 'code': classes[0], 'classes': classes,
                               'severity': 'MAJOR' if set(classes) & set(MAJOR) else 'MINOR'})
    total = len(set(a) | set(b))
    compared = Counter(d for d, _ in set(a) | set(b))
    differing = Counter(r['document'] for r in rows);major = Counter(r['document'] for r in rows if r['severity'] == 'MAJOR')
    per_document = [{'document': d, 'compared': n, 'disagreements': differing[d], 'major': major[d],
                     'agreement_rate': round((n - differing[d]) / n, 3)} for d, n in sorted(compared.items())]
    return {'status': 'AGREE' if not rows else 'DISAGREE', 'compared': total,
            'agreement_rate': round((total - len(rows)) / total, 3) if total else 1.0,
            'major': sum(r['severity'] == 'MAJOR' for r in rows), 'minor': sum(r['severity'] == 'MINOR' for r in rows),
            'by_class': {c: n for c in CLASSES if (n := sum(c in r['classes'] for r in rows))},
            'documents': per_document, 'disagreements': rows}


def service_key(named):
    """The service a CloudFormation type or a service name means: AWS::Lambda::Function, Lambda and AWS Lambda are one."""
    named = named.strip()
    if named.startswith('AWS::'):return named.split('::')[1].casefold()
    return named.replace(' ', '').casefold().removeprefix('amazon').removeprefix('aws')


def service_same(x, y):return service_key(x) == service_key(y)


def view(drawings, document=None):
    """The agent's view: one line per element with its kind, texts, frames and ends, and each visual's graph."""
    lines_ = [VIEW_KEY, '']
    for doc_id, found in drawings.items():
        if document not in (None, doc_id) or not found.elements:continue
        lines_ += [f'## {doc_id}', f'extraction_sha256={found.sha256} structure={found.structure_review}'
                   + (f' structure_content_hash={found.structure_content_hash}' if found.structure_content_hash else '')]
        for ref, e in found.elements.items():
            parts = [ref, e['kind']]
            if e['geometry']:parts.append(f"geometry={e['geometry']}")
            for key in ('sheet', 'name'):
                if e[key]:parts.append(f'{key}={json.dumps(e[key], ensure_ascii=False)}')
            if e['text']:parts.append(f"text={json.dumps(e['text'], ensure_ascii=False)}")
            if e['alt']:parts.append(f"alt={json.dumps(e['alt'], ensure_ascii=False)}")
            points = line_points(e) if is_line(e) else None
            if points:parts.append(f'runs={cell(*points[0])}→{cell(*points[1])}')
            elif e['rect']:parts.append(f"at={cell(e['rect'][0], e['rect'][1])}:{cell(max(e['rect'][0], e['rect'][2] - .001), max(e['rect'][1], e['rect'][3] - .001))}")
            groups = [r for r in found.frames.get(ref, []) if found.elements[r]['kind'] == 'group']
            frames = [r for r in found.frames.get(ref, []) if r not in groups]
            if groups:parts.append('group=' + ','.join(groups))
            if frames:parts.append('inside=' + ','.join(frames[:6]))
            if any(e['ends']):parts.append('ends=' + '→'.join(x or '?' for x in e['ends']))
            if points and not (len(e['ends']) == 2 and all(e['ends'])):
                # Ends the original does not record: the drawings at each end, a guess to confirm on the image.
                guess = [near(found, p, ref) if not (e['ends'] and e['ends'][i]) else [e['ends'][i]] for i, p in enumerate(points)]
                parts.append('near=' + '→'.join('|'.join(g) or '?' for g in guess))
            heads = [where for where, mark in (('start', e['head']), ('end', e['tail'])) if mark]
            if heads:parts.append('arrowhead=' + ('both' if len(heads) == 2 else heads[0]))
            if e['dash']:parts.append(f"dash={e['dash']}")
            if e['image']:
                path = found.picture_path(ref);parts.append(f'image={path or e["image"]}')
            lines_.append('\t'.join(parts))
        for visual_id, visual in found.visuals.items():
            graph = visual['graph'] or {}
            evidence = [f'{x}={found.regions[x]}' if x in found.regions else x for x in visual['evidence']]
            method = (graph.get('reading') or {}).get('method')
            lines_.append(f"visual {visual_id}: kind={visual['kind']} sources={','.join(visual['sources'])}"
                          f" graph_nodes={len(graph.get('nodes', []) or [])}" + (f' graph_reading={method}' if method else '')
                          + (f" evidence={','.join(evidence)}" if evidence else ' evidence=none'))
        graphs = {r: v for v, visual in found.visuals.items() if visual['graph'] for r in visual['sources']}
        pictures = [r for r, e in found.elements.items() if e['kind'] == 'picture' and not e['alt'] and not e['text']]
        if pictures:
            lines_.append('pictures without text or alternative text: '
                          + ', '.join(f'{r} (graph in visual {graphs[r]})' if r in graphs else f'{r} (no graph)' for r in pictures))
        lines_.append('')
    return '\n'.join(lines_) + '\n'


VIEW_KEY = ('# at=the anchor\'s cells (a group member: its place within the group); runs=a line\'s start→end cell; '
            'ends=start→end the original records; near=the smallest drawings at a line end the original does not record, '
            'a guess to confirm on the image; arrowhead=start, end or both; group=the group drawings holding it; '
            'inside=the frames around it, innermost first. A picture with no graph needs no vision reading unless it is mapped.')

# A rough size of one element and one document in a ledger written with indentation, to warn before a reading
# outgrows the ledger's limit.
ELEMENT_BYTES, DOCUMENT_BYTES = 240, 600


def preflight(drawings, ledger=None):
    """What reading the drawings will need, told before any worker starts: per CURRENT document with drawings, the
    pictures nothing reads yet, the lines whose ends only an image shows, the structure's state and the ledger's
    size; with an existing ledger, which of its documents still hold. A picture without text needs an accepted ARP4
    graph only when the ledger maps it, so those pictures are the ones to look at first, not failures."""
    out = Findings();documents = []
    listed = {d.document: d for d in ledger.documents} if ledger else {}
    for doc_id, found in drawings.items():
        if not found.elements:continue
        graphs = {r for v in found.visuals.values() if v['graph'] for r in v['sources']}
        unread = [r for r, e in found.elements.items() if e['kind'] == 'picture' and not e['alt'] and not e['text']]
        no_graph = [r for r in unread if r not in graphs]
        open_ends = [r for r, e in found.elements.items() if is_line(e) and not (len(e['ends']) == 2 and all(e['ends']))]
        evidence = sorted({x for v in found.visuals.values() for x in v['evidence']})
        row = {'document': doc_id, 'elements': len(found.elements),
               'kinds': dict(sorted(Counter(e['kind'] for e in found.elements.values()).items())),
               'structure': found.structure_review, 'visuals': len(found.visuals), 'pictures_without_text': len(unread),
               'pictures_without_graph': len(no_graph), 'lines_without_recorded_ends': len(open_ends),
               'rendered_evidence': len(evidence), 'estimated_ledger_bytes': DOCUMENT_BYTES + ELEMENT_BYTES * len(found.elements),
               # Nothing here means the document may draw nothing of the system: a candidate for NOT_ARCHITECTURE,
               # which only the two readings and the review decide.
               'architecture_signs': architecture_signs(found)}
        if no_graph:out.warn('PICTURE_WITHOUT_GRAPH', doc_id, count=len(no_graph), refs=no_graph[:20])
        if open_ends and not evidence:out.warn('LINE_ENDS_WITHOUT_EVIDENCE', doc_id, count=len(open_ends), refs=open_ends[:20])
        if found.visuals and found.structure_content_hash is None:out.warn('STRUCTURE_NOT_ACCEPTED', doc_id, structure=found.structure_review)
        if ledger is not None:
            doc = listed.get(doc_id)
            row['ledger'] = ('NOT_LEDGERED' if doc is None else 'LEDGER_STALE' if doc.extraction_sha256 != found.sha256
                             else 'STRUCTURE_STALE' if doc.structure_content_hash and doc.structure_content_hash != found.structure_content_hash
                             else 'CURRENT')
            if row['ledger'] != 'CURRENT':
                out.warn(row['ledger'], doc_id, **({'expected': found.structure_content_hash, 'recorded': doc.structure_content_hash}
                                                   if row['ledger'] == 'STRUCTURE_STALE' else {}))
        documents.append(row)
    estimate = 200 + sum(d['estimated_ledger_bytes'] for d in documents)
    # Each document has its own part ledger; a workspace that keeps a single ledger holds them all in one file.
    for d in documents:
        if d['estimated_ledger_bytes'] > LEDGER_LIMIT:out.fail('DOCUMENT_OVER_LIMIT', d['document'], estimated_bytes=d['estimated_ledger_bytes'], limit=LEDGER_LIMIT)
    if estimate > LEDGER_LIMIT:out.warn('SINGLE_LEDGER_OVER_LIMIT', estimated_bytes=estimate, limit=LEDGER_LIMIT)
    totals = {k: sum(d[k] for d in documents) for k in ('elements', 'pictures_without_text', 'pictures_without_graph',
                                                         'lines_without_recorded_ends')}
    return {'contract': 'diagram-preflight/1', 'status': out.status, 'documents_with_drawings': len(documents), **totals,
            'estimated_ledger_bytes': estimate, 'ledger_limit': LEDGER_LIMIT, 'findings': out.rows, 'documents': documents}


def brief(rows, limit=20, offset=0):
    """Findings told by code and by document, with a page of them in full, failures first; the rest are counted."""
    def rank(severity):return 0 if severity in ('FAIL', 'MAJOR') else 1
    ordered = sorted(rows, key=lambda r:rank(r['severity']))
    by_code = Counter((r['severity'], r['code']) for r in rows)
    return {'total': len(rows), 'by_code': [{'severity': s, 'code': c, 'count': n} for (s, c), n in
                                            sorted(by_code.items(), key=lambda x:(rank(x[0][0]), -x[1], x[0][1]))],
            'by_document': dict(Counter(r['document'] for r in rows if r.get('document')).most_common()),
            'offset': offset, 'shown': ordered[offset:offset + limit], 'omitted': max(0, len(rows) - offset - limit)}


def asks_state(workspace):
    """Per ask ID of the workspace's asks ledger: OPEN, HELD or ANSWERED from the recorded answers."""
    from . import asks as asks_module
    workspace = Path(workspace)
    path = asks_module.ledger_path(workspace)
    if not path.is_file():return {}
    try:ledger = asks_module.load_ledger(path.read_bytes())
    except (ValueError, asks_module.InputError):return {}
    state = {a.id: 'OPEN' for a in ledger.asks}
    for records in asks_module.read_records(workspace):
        for entry in records.entries:
            if entry.ask in state:state[entry.ask] = 'HELD' if entry.action == 'HOLD' else 'ANSWERED'
    return state


def folder(workspace):return Path(workspace) / 'diagrams'
def ledger_path(workspace):return folder(workspace) / 'ledger.json'
def second_path(workspace):return folder(workspace) / 'reading-2.json'
def review_path(workspace, digest):return folder(workspace) / f'review-{digest[:12]}.json'


class Part:
    """Where the readings of some documents live. A workspace that already holds diagrams/ledger.json or
    reading-2.json keeps that single ledger for every document; any other workspace reads each CURRENT document
    with drawings in its own folder diagrams/parts/NAME, so one document is read, compared, reviewed and read
    again without touching the others. Each part holds ledger.json (the reading the design uses), reading-2.json
    (the independent one), review-<sha12>.json, adoption records and retired/ (readings taken out of use)."""

    def __init__(self, folder, documents=None):self.folder, self.documents = Path(folder), documents
    @property
    def first(self):return self.folder / 'ledger.json'
    @property
    def second(self):return self.folder / 'reading-2.json'
    @property
    def label(self):return self.documents[0] if self.documents else 'diagrams'
    def review(self, digest):return self.folder / f'review-{digest[:12]}.json'
    def path(self, reading):return self.first if reading == 'ledger' else self.second


def part_name(document):
    """A folder name for a document's part: readable where the ID is, and unique by its hash whatever the ID holds."""
    readable = re.sub(r'[^A-Za-z0-9._-]+', '-', unicodedata.normalize('NFKC', document)).strip('-.')[:40]
    return f"{readable}-{hashlib.sha256(document.encode('utf-8')).hexdigest()[:8]}" if readable else hashlib.sha256(document.encode('utf-8')).hexdigest()[:12]


def single(workspace):return ledger_path(workspace).is_file() or second_path(workspace).is_file()


def parts(workspace, drawings):
    """The parts of a workspace for the CURRENT documents with drawings."""
    if single(workspace):return [Part(folder(workspace))]
    return [Part(folder(workspace) / 'parts' / part_name(d), [d]) for d, found in drawings.items() if found.elements]


def part_of(workspace, document):
    if single(workspace):return Part(folder(workspace))
    return Part(folder(workspace) / 'parts' / part_name(document), [document])


def ledger_files(workspace):
    """Every reading the design uses (each part's ledger.json), whether or not its document is still CURRENT."""
    if single(workspace):return [ledger_path(workspace)] if ledger_path(workspace).is_file() else []
    return sorted((folder(workspace) / 'parts').glob('*/ledger.json'))


def retire(part, reading):
    """Move a reading into the part's retired/ folder: (its sha256, its author or None, where it went)."""
    path = part.path(reading)
    if not path.is_file():raise InputError(f'NO_READING: {path.name} does not exist')
    raw = path.read_bytes();digest = sha(raw)
    try:author = load(raw).author.actor.strip()
    except InputError:author = None
    target = part.folder / 'retired' / f'{digest[:12]}-{reading}.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():path.unlink()
    else:path.replace(target)
    return digest, author, target.relative_to(part.folder).as_posix()


def record_adoption(part, **fields):
    """Write an adoption record into the part's adoptions/ folder, never over an earlier one."""
    entry = Adoption(contract='diagram-adoption/1', document=part.documents[0] if part.documents else None, recorded_at=stamp(), **fields)
    folder_ = part.folder / 'adoptions';folder_.mkdir(parents=True, exist_ok=True)
    base = entry.recorded_at.replace(':', '').replace('-', '') + '-' + entry.action.lower()
    path = folder_ / f'{base}.json';n = 1
    while path.exists():n += 1;path = folder_ / f'{base}-{n}.json'
    path.write_bytes(dump(entry.model_dump(exclude_none=True)))
    return path


def workspace_part(workspace, document):
    """The part a command names: --document in a workspace of parts, nothing in one with a single ledger."""
    if single(workspace):
        if document:raise InputError('the workspace keeps a single ledger in diagrams/; leave out --document')
        return Part(folder(workspace))
    if not document:raise InputError('give --document: the workspace reads each document in its own part')
    return part_of(workspace, document)


def workspace_report(workspace, arp_root, set_raw, design):
    """Coverage of the workspace's ledgers, or None when no CURRENT document has drawings and no ledger exists. A draft
    workspace of part ledgers is covered through its picture triage instead (diagram_triage.draft_coverage)."""
    from .flow import is_draft, load as load_config
    if not single(workspace) and is_draft(load_config(workspace)):
        from .diagram_triage import draft_coverage
        return draft_coverage(workspace, arp_root, set_raw, design)
    drawings = read_documents(arp_root, set_raw)
    found = [p for p in parts(workspace, drawings) if p.first.is_file()]
    if not found:
        if not any(f.elements for f in drawings.values()):return None
        out = Findings()
        for document, f in drawings.items():
            if f.elements:out.fail('DIAGRAM_NOT_LEDGERED', document, count=len(f.elements))
        return {'contract': 'diagram-coverage/1', 'status': 'FAIL', 'counts': {}, 'covered': 0, 'coverage_percent': 0.0,
                'design_counts': design_counts(Design(design or {})), 'findings': out.rows}
    reviews = []
    for part in found:
        raw = part.first.read_bytes();ledger = load(raw);digest = sha(raw)
        reviews.append((ledger, load_review(part.review(digest).read_bytes()) if part.review(digest).is_file() else None, digest))
    if single(workspace):
        ledger, review, digest = reviews[0]
        return coverage(ledger, drawings, design or {}, asks=asks_state(workspace), review=review, ledger_sha256=digest)
    # A part with no ledger yet leaves its document unledgered in the whole, which the check fails.
    return coverage(combined([r[0] for r in reviews]), drawings, design or {}, asks=asks_state(workspace), reviews=reviews)


def emit(report, key, args):
    """A report on standard output: by default its summary and a page of its rows, so thousands of findings never
    flood a terminal or an agent's context; --full prints every row, --output also keeps them all in a new file."""
    if args.output:
        output = Path(args.output)
        if output.exists():raise InputError('output already exists; use a fresh path')
        output.parent.mkdir(parents=True, exist_ok=True);output.write_bytes(dump(report))
    if args.full:
        shown = report
    else:
        rows = [r for r in report[key] if args.document in (None, r.get('document')) and args.code in (None, r.get('code'))]
        shown = {**{k: v for k, v in report.items() if k not in (key, 'documents')}, key: brief(rows, max(args.limit, 0), max(args.offset, 0))}
        if 'documents' in report:
            documents = [d for d in report['documents'] if args.document in (None, d['document'])]
            shown['documents'] = documents[:50]
            if len(documents) > 50:shown['documents_omitted'] = len(documents) - 50
        if args.output:shown['full_report'] = str(args.output)
    sys.stdout.buffer.write((json.dumps(shown, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] in (['triage'], ['look']):
        # The picture triage of draft mode (diagram_triage.py) answers these two.
        from .diagram_triage import main as triage_main
        return triage_main(argv)
    parser = argparse.ArgumentParser(prog='aws-design diagram', description='Diagram ledger: every drawing of the CURRENT documents and what the design makes of it'
                                     ' (triage and look: the picture triage of draft mode, see aws-design diagram triage --help)')
    sub = parser.add_subparsers(dest='command', required=True)
    def arp(p):
        p.add_argument('--arp-root', required=True);p.add_argument('--source-set', required=True, help='approved source set')
    p = sub.add_parser('schema', help='print the JSON Schema of the ledger or review');p.add_argument('--kind', choices=['ledger', 'review'], default='ledger')
    def paged(p):
        p.add_argument('--full', action='store_true', help='print every finding instead of the summary')
        p.add_argument('--output', help='also write the full report to this new file')
        p.add_argument('--limit', type=int, default=20, help='findings printed in full (default 20)')
        p.add_argument('--offset', type=int, default=0, help='skip this many findings before printing')
        p.add_argument('--document', help='only the findings of this document');p.add_argument('--code', help='only the findings of this code')
    p = sub.add_parser('view', help="the worker's view of the drawings");arp(p);p.add_argument('--document')
    p = sub.add_parser('preflight', help='before reading: what each document will need, and the ledger size');arp(p)
    p.add_argument('--ledger', help='an existing ledger: which of its documents still hold');paged(p)
    p = sub.add_parser('check', help='check a ledger against the drawings, and with --design the coverage');arp(p)
    p.add_argument('--ledger', required=True);p.add_argument('--design');p.add_argument('--workspace', help='for the asks answers');paged(p)
    p.add_argument('--for-document', action='append', help="a part ledger: the document it reads (repeat for several); others are not expected")
    p = sub.add_parser('review', help='record an independent review of a ledger');arp(p)
    p.add_argument('--for-document', action='append', help='a part ledger: the document it reads')
    p.add_argument('--ledger', required=True);p.add_argument('--decision', choices=['accepted', 'rejected'], required=True)
    p.add_argument('--actor', required=True);p.add_argument('--reason', required=True);p.add_argument('--output', required=True)
    p = sub.add_parser('compare', help='elements two independent ledgers read differently')
    p.add_argument('--ledger', action='append', required=True, help='give exactly two ledgers by different actors');paged(p)
    p = sub.add_parser('coverage', help="write the workspace's coverage report");p.add_argument('--workspace', required=True)
    p.add_argument('--output', required=True, help='fresh directory')
    def deciding(p):
        p.add_argument('--workspace', required=True);p.add_argument('--document', help="the part's document (a workspace of parts)")
        p.add_argument('--actor', required=True);p.add_argument('--reason', required=True)
    p = sub.add_parser('retire', help='take a reading out of use into retired/, so a new one is written to a fresh file');deciding(p)
    p.add_argument('--reading', choices=['ledger', 'reading-2'], required=True)
    p = sub.add_parser('adopt', help='make the independent reading the one the design uses; the former one is retired');deciding(p)
    p = sub.add_parser('start', help="draft mode: write a document's ledger by rule (kind, text, frames, line ends), to correct instead of writing one by hand")
    p.add_argument('--workspace', required=True);p.add_argument('--document', required=True, help='the document ID exactly as the flow names it')
    p.add_argument('--replace', action='store_true', help='retire the existing reading and start again from the rule reading')
    for name in ('view', 'preflight', 'check', 'review', 'coverage', 'adopt'):
        sub.choices[name].add_argument('--progress', action='store_true', help='JSON lines of progress on standard error')
    args = parser.parse_args(argv)
    Progress.stream = sys.stderr if getattr(args, 'progress', False) else None
    try:
        if args.command == 'schema':
            print(json.dumps((Ledger if args.kind == 'ledger' else LedgerReview).model_json_schema(), ensure_ascii=False, indent=2));return 0
        if args.command == 'start':
            from .diagram_rules import InputError as RuleError, start
            try:result = start(args.workspace, args.document, args.replace)
            except RuleError as exc:raise InputError(str(exc)) from None
            sys.stdout.buffer.write((json.dumps(result, ensure_ascii=False) + '\n').encode('utf-8'));return 0
        if args.command == 'compare':
            if len(args.ledger) != 2:raise InputError('compare needs exactly two --ledger files')
            report = compare(*(load(Path(p).read_bytes()) for p in args.ledger))
            emit(report, 'disagreements', args);return 0 if report['status'] == 'AGREE' else 3
        if args.command in ('retire', 'adopt'):
            workspace = Path(args.workspace);part = workspace_part(workspace, args.document)
            if args.command == 'retire':
                digest, author, where = retire(part, args.reading)
                path = record_adoption(part, action='RETIRE', retired_reading=args.reading, retired_sha256=digest, retired_author=author,
                                       retired_to=where, actor=args.actor.strip(), reason=args.reason)
                print(json.dumps({'retired': where, 'record': str(path)}, ensure_ascii=False));return 0
            from . import flow
            config = flow.load(workspace)
            if not part.second.is_file():raise InputError('NO_READING: reading-2.json does not exist')
            raw = part.second.read_bytes();adopted = load(raw)
            drawings = read_documents(Path(config['arp_root']), (workspace / 'sources' / 'set.json').read_bytes())
            if check(adopted, drawings, part.documents).status == 'FAIL':raise InputError('CHECK_FAILED: only a reading that passes its check is adopted')
            retired = retire(part, 'ledger') if part.first.is_file() else None
            part.second.replace(part.first)
            path = record_adoption(part, action='ADOPT', adopted_sha256=sha(raw), adopted_author=adopted.author.actor.strip(),
                                   **({'retired_reading': 'ledger', 'retired_sha256': retired[0], 'retired_author': retired[1],
                                       'retired_to': retired[2]} if retired else {}), actor=args.actor.strip(), reason=args.reason)
            print(json.dumps({'adopted': str(part.first), 'retired': retired[2] if retired else None, 'record': str(path)}, ensure_ascii=False))
            return 0
        if args.command == 'coverage':
            from . import flow
            from .document_normalize import parse
            workspace = Path(args.workspace);config = flow.load(workspace)
            if not config.get('arp_root'):raise InputError('the workspace has no ARP4 root')
            design_path = flow.generation_input(workspace, config)
            design = parse(design_path.read_bytes()) if design_path and design_path.is_file() else {}
            report = workspace_report(workspace, Path(config['arp_root']), (workspace / 'sources' / 'set.json').read_bytes(), design)
            if report is None:print(json.dumps({'status': 'NOT_APPLICABLE'}));return 0
            output = Path(args.output)
            if output.exists():raise InputError('output already exists; use a fresh directory')
            output.mkdir(parents=True)
            (output / 'diagram-coverage.json').write_bytes(dump(report));(output / 'diagram-coverage.md').write_text(render(report), encoding='utf-8')
            print(json.dumps({'status': report['status'], 'coverage_percent': report['coverage_percent']}));return 0 if report['status'] != 'FAIL' else 3
        drawings = read_documents(Path(args.arp_root), Path(args.source_set).read_bytes())
        if args.command == 'view':
            sys.stdout.buffer.write(view(drawings, args.document).encode('utf-8'));return 0
        if args.command == 'preflight':
            report = preflight(drawings, load(Path(args.ledger).read_bytes()) if args.ledger else None)
            emit(report, 'findings', args);return 0 if report['status'] != 'FAIL' else 2
        for document in getattr(args, 'for_document', None) or []:
            # A wrong input is told apart from a wrong ledger, before the ledger is read: no reading can fix it.
            if document not in drawings or not drawings[document].elements:
                known = sorted(d for d, f in drawings.items() if f.elements)
                raise InputError(f'INPUT_DOCUMENT_NOT_CURRENT: {document} is not a CURRENT document with drawings in this source set. The ledger is '
                                 'not at fault and reading again will not help: use the document ID and the source set the flow names '
                                 f'(aws-design flow status). CURRENT documents with drawings: {json.dumps(known[:30], ensure_ascii=False)}'
                                 + (f' and {len(known) - 30} more' if len(known) > 30 else ''))
        raw = Path(args.ledger).read_bytes();ledger = load(raw)
        if args.command == 'check':
            if args.design:
                from .document_normalize import parse
                report = coverage(ledger, drawings, parse(Path(args.design).read_bytes()),
                                  asks=asks_state(args.workspace) if args.workspace else {}, review=None, ledger_sha256=sha(raw))
                # The review comes after the check; its absence is not this command's finding.
                kept = Findings();kept.rows = [f for f in report['findings'] if f['code'] != 'REVIEW_MISSING']
                report['findings'], report['status'] = kept.rows, kept.status
            else:
                found = check(ledger, drawings, args.for_document);report = {'status': found.status, 'findings': found.rows}
                failed = {r['code'] for r in found.rows if r['severity'] == 'FAIL'}
                if failed and failed <= set(NOT_THIS_DOCUMENT):
                    # The ledger names another document than the one it is checked for: an input mismatch, not a reading to redo.
                    report.update(cause='INPUT_MISMATCH', ledger_documents=sorted({d.document for d in ledger.documents})[:20],
                                  expected_documents=args.for_document or sorted(d for d, f in drawings.items() if f.elements)[:20],
                                  hint='The ledger does not belong to the document or source set it is checked against. Do not read the drawings '
                                       'again: set "document" to the expected ID exactly, or in draft mode run aws-design diagram start --workspace WS '
                                       '--document ID --replace.')
            emit(report, 'findings', args);return 0 if report['status'] != 'FAIL' else 2
        if args.actor.strip() == ledger.author.actor.strip():raise InputError('REVIEWER_IS_AUTHOR: use an independent reviewer')
        found = check(ledger, drawings, args.for_document)
        if args.decision == 'accepted' and found.status == 'FAIL':raise InputError('CHECK_FAILED: a ledger with failures cannot be accepted')
        output = Path(args.output)
        if output.exists():raise InputError('output already exists; use a fresh path')
        review = LedgerReview(contract='diagram-review/1', ledger_sha256=sha(raw), decision=args.decision, actor=args.actor.strip(),
                              author=ledger.author.actor.strip(), reason=args.reason, recorded_at=stamp())
        output.parent.mkdir(parents=True, exist_ok=True);output.write_bytes(dump(review.model_dump()))
        print(json.dumps({'review': args.decision, 'ledger_sha256': review.ledger_sha256}));return 0
    except ValidationError as exc:
        print(json.dumps({'status': 'ERROR', 'message': 'CONTRACT_INVALID', 'errors': problems(exc)}, ensure_ascii=False));return 2
    except (InputError, json.JSONDecodeError, OSError) as exc:
        message = str(exc) if isinstance(exc, InputError) else type(exc).__name__
        print(json.dumps({'status': 'ERROR', 'message': message}, ensure_ascii=False));return 2


if __name__ == '__main__':
    raise SystemExit(main())
