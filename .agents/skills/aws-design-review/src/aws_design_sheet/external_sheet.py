"""External design sheets parsed by ARP4 to a 1.1 input, through agent-cited cells.

ARP4 extracts the workbook's cells and a reviewed table structure. A worker agent writes
an items file that cites cells by ID and never copies their values. This module checks
every claim against the extraction, maps only dictionary-approved labels, and writes the
1.1 input, a source trace for the existing generator, the mapping table and a coverage
report. Values are never inferred; blanks and formulas are never adopted as values.
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

from pydantic import Field, JsonValue, ValidationError, model_validator

from .models import StrictModel

CONTRACT_VERSION = '1'
EXTRACTION_SCHEMA = '2'
CELL = r'^s([1-9][0-9]{0,3})-([A-Z]{1,3})([1-9][0-9]{0,6})$'
CELLS = r'^s([1-9][0-9]{0,3})-([A-Z]{1,3})([1-9][0-9]{0,6})(?::([A-Z]{1,3})([1-9][0-9]{0,6}))?$'
STATES = ('LITERAL', 'UNDECIDED', 'NOT_APPLICABLE', 'DEFAULT', 'BLANK', 'FORMULA', 'RESOURCE_REF', 'SECRET_REF', 'SECRET_VALUE')
# Built-in value words, compared after normalization. A dictionary may add words.
STATE_WORDS = {
    'UNDECIDED': ['未定', '未決定', 'TBD', '要検討', '検討中', '調整中'],
    'NOT_APPLICABLE': ['-', '－', 'ー', '―', 'N/A', 'NA', '対象外', '不要', '該当なし'],
    'DEFAULT': ['デフォルト', '既定', '既定値', 'Default', 'AWS既定', 'AWS既定値'],
}
NOT_WRITTEN = {'BLANK': 'BLANK_NOT_CONVERTED', 'FORMULA': 'FORMULA_RESULT_NOT_ADOPTED', 'SECRET_VALUE': 'SECRET_VALUE_NOT_COPIED'}
# The ARP4 extraction contract has no field for these; their absence is reported, never assumed.
UNEXTRACTED = ['data_validations', 'defined_names', 'sheet_protection', 'workbook_protection', 'external_links']
REDACTED = '[秘密値: 記録しない]'

ID = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_-]{0,63}$')]
ItemID = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_.-]{0,127}$')]
Hash = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
CellRef = Annotated[str, Field(pattern=CELL)]
CellRange = Annotated[str, Field(pattern=CELLS)]
Pointer = Annotated[str, Field(pattern=r'^(/[^/]+)+$')]
Convert = Literal['string', 'integer', 'number', 'boolean']


class InputError(ValueError):
    pass


class Binding(StrictModel):
    document: str = Field(min_length=1)
    extraction_sha256: Hash
    structure_content_hash: Hash


class Author(StrictModel):
    actor: str = Field(min_length=1)
    model: str = ''


class SheetResource(StrictModel):
    id: ID
    type: str
    name_cell: CellRef | None = None
    evidence_cells: list[CellRef] = Field(default_factory=list)
    region: str | None = Field(default=None, pattern=r'^[a-z]{2}(?:-gov)?-[a-z]+-\d+$')


class Condition(StrictModel):
    label_cell: CellRef
    value_cell: CellRef


class Proposal(StrictModel):
    convert: Convert
    value_map: dict[str, JsonValue] = Field(default_factory=dict)
    units: list[str] = Field(default_factory=list)


class Mapping(StrictModel):
    entry: str | None = None
    proposal: Proposal | None = None

    @model_validator(mode='after')
    def one(self):
        if (self.entry is None) == (self.proposal is None):raise ValueError('mapping needs exactly one of entry or proposal')
        return self


class Item(StrictModel):
    id: ItemID
    resource: ID
    label_cells: list[CellRef] = Field(min_length=1)
    value_cell: CellRef
    unit_cell: CellRef | None = None
    note_cells: list[CellRef] = Field(default_factory=list)
    conditions: list[Condition] = Field(default_factory=list)
    paths: list[Pointer] = Field(min_length=1)
    state: Literal[STATES]
    ref: ID | None = None
    mapping: Mapping
    reason: str = ''

    @model_validator(mode='after')
    def shape(self):
        if (self.state == 'RESOURCE_REF') != (self.ref is not None):raise ValueError('ref is required for RESOURCE_REF only')
        return self


class Retained(StrictModel):
    id: ItemID
    cells: list[CellRange] = Field(default_factory=list)
    resources: list[ID] = Field(default_factory=list)
    reason: str = Field(min_length=1)
    sensitive: bool = False

    @model_validator(mode='after')
    def anchored(self):
        if not self.cells and not self.resources:raise ValueError('cite cells or resources')
        return self


class Extension(Retained):
    category: Literal['BUSINESS', 'SERVICE_SPECIFIC', 'REFERENCE_ONLY', 'OTHER']
    follow_up: str = ''


class Unmapped(Retained):
    category: Literal['NO_CFN_PROPERTY', 'AMBIGUOUS', 'NEEDS_CONFIRMATION', 'UNREADABLE']
    follow_up: str = Field(min_length=1)


class Excluded(StrictModel):
    cells: list[CellRange] = Field(min_length=1)
    reason: str = Field(min_length=1)


class ItemsFile(StrictModel):
    schema_version: Literal['1']
    binding: Binding
    author: Author
    sheet_version_cell: CellRef | None = None
    resources: list[SheetResource] = Field(default_factory=list)
    items: list[Item] = Field(default_factory=list)
    extensions: list[Extension] = Field(default_factory=list)
    unmapped: list[Unmapped] = Field(default_factory=list)
    excluded: list[Excluded] = Field(default_factory=list)


class When(StrictModel):
    label: str = Field(min_length=1)
    values: list[str] = Field(min_length=1)


class EntryEvidence(StrictModel):
    document: str
    extraction_sha256: Hash
    item_id: str
    label_cells: list[CellRef]


class Entry(StrictModel):
    id: str = Field(pattern=r'^[a-z][a-z0-9-]{0,127}$')
    resource_type: str
    labels: list[str] = Field(min_length=1)
    paths: list[Pointer] = Field(min_length=1)
    convert: Convert
    value_map: dict[str, JsonValue] = Field(default_factory=dict)
    units: list[str] = Field(default_factory=list)
    when: list[When] = Field(default_factory=list)
    approved_by: str = Field(min_length=1)
    approved_at: str = Field(min_length=1)
    evidence: EntryEvidence | None = None


class Dictionary(StrictModel):
    schema_version: Literal['1']
    state_words: dict[Literal['UNDECIDED', 'NOT_APPLICABLE', 'DEFAULT'], list[str]] = Field(default_factory=dict)
    entries: list[Entry] = Field(default_factory=list)

    @model_validator(mode='after')
    def unique(self):
        if len({e.id for e in self.entries}) != len(self.entries):raise ValueError('duplicate dictionary entry ID')
        seen = {}
        for state, words in STATE_WORDS.items():
            for word in [*words, *self.state_words.get(state, [])]:
                if seen.setdefault(norm(word), state) != state:raise ValueError('state word assigned to two states')
        return self


class Review(StrictModel):
    schema_version: Literal['1']
    items_sha256: Hash
    decision: Literal['accepted', 'rejected']
    actor: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    recorded_at: str


def sha(raw):return hashlib.sha256(raw).hexdigest()


def norm(text):
    """Comparison form of labels and value words: NFKC, no whitespace, case-folded."""
    return re.sub(r'\s+', '', unicodedata.normalize('NFKC', str(text))).casefold()


def label_norm(text):
    """Labels also drop section and footnote marks, which carry no meaning for mapping."""
    return norm(text).strip('■□●◆◇▼▶・※*＊:：')


def column(letters):
    n = 0
    for ch in letters:n = n * 26 + ord(ch) - 64
    return n


def letters(n):
    out = ''
    while n:n, r = divmod(n - 1, 26);out = chr(65 + r) + out
    return out


def parse_pointer(path):
    return [int(t) if t.isdigit() else t.replace('~1', '/').replace('~0', '~') for t in path.split('/')[1:]]


def pattern_of(path):
    return '/' + '/'.join('*' if isinstance(p, int) else str(p).replace('~', '~0').replace('/', '~1') for p in parse_pointer(path))


class Sheetbook:
    """ARP4 extraction and structure, bound by hash; cell values are read here only."""

    def __init__(self, extraction_raw, structure_raw, document_raw=None):
        import yaml
        self.extraction_sha256 = sha(extraction_raw)
        extraction = json.loads(extraction_raw)
        if str(extraction.get('schema_version')) != EXTRACTION_SCHEMA:raise InputError('unsupported ARP extraction schema version')
        self.parser = extraction.get('parser', '')
        structure = yaml.safe_load(structure_raw)
        if not isinstance(structure, dict) or structure.get('schema_version') != 1:raise InputError('unsupported ARP structure schema version')
        if structure.get('extraction_hash') != self.extraction_sha256:raise InputError('STRUCTURE_STALE: structure was made from another extraction')
        self.document = structure.get('document', '')
        self.source = structure.get('source') or {}
        review = structure.get('review') or {}
        self.structure_review = {'status': review.get('status', 'pending'), 'actor': review.get('actor')}
        self.structure_content_hash = review.get('content_hash') if review.get('status') == 'accepted' else None
        if document_raw is not None:
            record = yaml.safe_load(document_raw)
            if record.get('extraction') != self.extraction_sha256 or (record.get('source') or {}).get('sha256') != self.source.get('sha256'):
                raise InputError('DOCUMENT_RECORD_MISMATCH: ARP document record disagrees with extraction or structure')
        self.sheets, self.cells, self.merged = [], {}, {}
        for number, sheet in enumerate(extraction.get('sheets', []), 1):
            styles = sheet.get('styles', [])
            self.sheets.append({'number': number, 'name': sheet['name'], 'state': sheet.get('state', 'visible')})
            for cell in sheet.get('cells', []):
                cid = f"s{number}-{cell['address']}"
                self.cells[cid] = {'id': cid, 'sheet': sheet['name'], 'sheet_number': number, 'address': cell['address'],
                                   'value': cell.get('value'), 'formula': cell.get('formula'), 'type': cell.get('type'),
                                   'number_format': cell.get('number_format', 'General'),
                                   'strike': bool(styles[cell['style']].get('strike')) if isinstance(cell.get('style'), int) and cell['style'] < len(styles) else False}
            for merge in sheet.get('merges', []):
                first, _, last = merge.partition(':')
                for cid in self.expand(f's{number}-{first}:{last}' if last else f's{number}-{first}', existing=False)[1:]:
                    self.merged[cid] = f's{number}-{first}'
        self.headers, self.roles = {}, {}
        for element in structure.get('elements', []):
            number = next((s['number'] for s in self.sheets if s['name'] == element.get('sheet')), None)
            for cell in element.get('cells', []):
                cid = f"s{number}-{cell['address']}"
                self.headers[cid] = [h for h in cell.get('headers', [])]
                self.roles[cid] = cell.get('role')

    def sheet_of(self, cid):
        return self.sheets[int(re.match(CELL, cid).group(1)) - 1]

    def known_sheet(self, cid):
        return int(re.match(CELLS, cid).group(1)) <= len(self.sheets)

    def expand(self, ref, existing=True):
        m = re.match(CELLS, ref)
        number, c1, r1 = int(m.group(1)), column(m.group(2)), int(m.group(3))
        c2, r2 = (column(m.group(4)), int(m.group(5))) if m.group(4) else (c1, r1)
        out = [f's{number}-{letters(c)}{r}' for r in range(min(r1, r2), max(r1, r2) + 1) for c in range(min(c1, c2), max(c1, c2) + 1)]
        return [c for c in out if c in self.cells] if existing else out

    def text(self, cid):
        cell = self.cells.get(cid)
        if cell is None or cell['value'] is None:return ''
        value = cell['value']
        if isinstance(value, bool):return 'TRUE' if value else 'FALSE'
        if isinstance(value, float) and value.is_integer():return str(int(value))
        return str(value)

    def empty(self, cid):
        cell = self.cells.get(cid)
        return cell is None or (cell['formula'] is None and cell['value'] in (None, ''))

    def nonempty(self):
        return [cid for cid, cell in self.cells.items() if not self.empty(cid)]

    def locate(self, cid):
        m = re.match(CELL, cid)
        return {'cell': cid, 'sheet': self.sheets[int(m.group(1)) - 1]['name'] if self.known_sheet(cid) else None,
                'address': f'{m.group(2)}{m.group(3)}'}


def load_dictionary(raw):
    if raw is None:return Dictionary(schema_version='1'), None
    return Dictionary.model_validate_json(raw), sha(raw)


def state_words(dictionary):
    out = {}
    for state, words in STATE_WORDS.items():
        for word in [*words, *dictionary.state_words.get(state, [])]:out[norm(word)] = state
    return out


def convert_value(book, cid, how, value_map):
    """Explicit conversion of one cell; raises ValueError with a code, never with the value."""
    cell = book.cells[cid];raw = cell['value'];key = norm(book.text(cid))
    mapped = {norm(k): v for k, v in value_map.items()}
    if key in mapped:return mapped[key]
    if how == 'string':
        if isinstance(raw, bool):raise ValueError('VALUE_NOT_CONVERTIBLE')
        return raw.strip() if isinstance(raw, str) else book.text(cid)
    if how == 'integer':
        if type(raw) is int:return raw
        if isinstance(raw, float) and raw.is_integer():return int(raw)
        if isinstance(raw, str) and re.fullmatch(r'[+-]?\d+', unicodedata.normalize('NFKC', raw).strip()):
            return int(unicodedata.normalize('NFKC', raw).strip())
        raise ValueError('VALUE_NOT_CONVERTIBLE')
    if how == 'number':
        if type(raw) in (int, float):return raw
        try:return float(unicodedata.normalize('NFKC', str(raw)).strip())
        except ValueError:raise ValueError('VALUE_NOT_CONVERTIBLE') from None
    if type(raw) is bool:return raw
    raise ValueError('VALUE_NOT_CONVERTIBLE')


def canonical(resource_type, paths, convert, value_map, units, when):
    return (resource_type, tuple(sorted({pattern_of(p) for p in paths})), convert,
            tuple(sorted((norm(k), json.dumps(v, sort_keys=True)) for k, v in value_map.items())),
            tuple(sorted({norm(u) for u in units})),
            tuple(sorted((label_norm(w['label']), tuple(sorted({norm(v) for v in w['values']}))) for w in when)))


def label_text(book, item):
    return ' / '.join(book.text(c) for c in item.label_cells)


def proposal_when(book, item):
    return [{'label': book.text(c.label_cell), 'values': [book.text(c.value_cell)]} for c in item.conditions]


class Result:
    def __init__(self):
        self.errors, self.warnings = [], []

    def error(self, code, where='', cells=()):self.errors.append({'code': code, 'where': where, 'cells': list(cells)})

    def warn(self, code, where='', cells=()):self.warnings.append({'code': code, 'where': where, 'cells': list(cells)})


def resolve_mapping(book, items_file, item, resource, dictionary):
    """Return (status, entry) where status is DICTIONARY, PROPOSED or an error code."""
    entries = {e.id: e for e in dictionary.entries}
    label = label_norm(label_text(book, item))
    if item.mapping.entry is not None:
        entry = entries.get(item.mapping.entry)
        if entry is None:return 'UNKNOWN_ENTRY', None
        if entry.resource_type != resource.type:return 'ENTRY_TYPE_MISMATCH', entry
        if label not in {label_norm(x) for x in entry.labels}:return 'LABEL_MISMATCH', entry
        if any(pattern_of(p) not in entry.paths for p in item.paths) or {pattern_of(p) for p in item.paths} != set(entry.paths):
            return 'PATH_NOT_IN_ENTRY', entry
        for w in entry.when:
            if not any(label_norm(book.text(c.label_cell)) == label_norm(w.label) and norm(book.text(c.value_cell)) in {norm(v) for v in w.values}
                       for c in item.conditions):
                return 'CONDITION_MISMATCH', entry
        return 'DICTIONARY', entry
    p = item.mapping.proposal
    wanted = canonical(resource.type, item.paths, p.convert, p.value_map, p.units, proposal_when(book, item))
    for entry in dictionary.entries:
        if label in {label_norm(x) for x in entry.labels} and canonical(
                entry.resource_type, entry.paths, entry.convert, entry.value_map, entry.units, [w.model_dump() for w in entry.when]) == wanted:
            return 'DICTIONARY', entry
    return 'PROPOSED', None


def rule(item, entry):
    """Conversion rule in force for an item: the approved entry, else its own proposal."""
    if entry is not None:return entry.convert, entry.value_map, entry.units
    p = item.mapping.proposal
    return p.convert, p.value_map, p.units


def check(book, items_file, dictionary, *, region=None):
    """Validate an items file. Messages carry codes and cell IDs, never cell values."""
    from .document_catalog import catalog
    from .document_normalize import secret_literal
    from .document_v11 import sensitive
    result = Result();words = state_words(dictionary)
    b = items_file.binding
    if book.structure_content_hash is None:result.error('STRUCTURE_NOT_ACCEPTED')
    if b.extraction_sha256 != book.extraction_sha256:result.error('BINDING_EXTRACTION_MISMATCH')
    if book.structure_content_hash and b.structure_content_hash != book.structure_content_hash:result.error('BINDING_STRUCTURE_MISMATCH')
    if b.document != book.document:result.error('BINDING_DOCUMENT_MISMATCH')
    ids = [r.id for r in items_file.resources]
    all_ids = [*(i.id for i in items_file.items), *(e.id for e in items_file.extensions), *(u.id for u in items_file.unmapped)]
    if len(ids) != len(set(ids)) or len(all_ids) != len(set(all_ids)):result.error('DUPLICATE_ID')
    resources = {r.id: r for r in items_file.resources}
    referenced = defaultdict(set);secret_cells = set()

    def cite(cid, how, where, *, may_be_empty=False):
        if not book.known_sheet(cid):result.error('UNKNOWN_SHEET', where, [cid]);return False
        if cid in book.merged:result.error('MERGED_NON_ANCHOR', where, [cid]);return False
        if cid not in book.cells and not may_be_empty:result.error('UNKNOWN_CELL', where, [cid]);return False
        referenced[cid].add(how)
        return True

    def cite_range(ref, how, where):
        if not book.known_sheet(ref):result.error('UNKNOWN_SHEET', where, [ref]);return
        cells = book.expand(ref)
        if not cells:result.error('EMPTY_RANGE', where, [ref])
        for cid in cells:referenced[cid].add(how)

    cat = {}
    def catalog_for(resource):
        key = resource.region or region
        if key not in cat:cat[key] = catalog(key)
        return cat[key]

    for r in items_file.resources:
        try:c = catalog_for(r)
        except Exception:result.error('UNKNOWN_REGION', r.id);continue
        if r.type not in c.schemas:result.error('UNKNOWN_RESOURCE_TYPE', r.id)
        if r.name_cell:cite(r.name_cell, 'resource', r.id)
        for cid in r.evidence_cells:cite(cid, 'resource', r.id)
    if items_file.sheet_version_cell:cite(items_file.sheet_version_cell, 'version', 'sheet_version_cell')
    value_owner, path_owner = {}, {}
    elements = defaultdict(set)  # array element -> member names some item gives
    for item in items_file.items:
        where = item.id
        resource = resources.get(item.resource)
        for cid in item.label_cells:cite(cid, 'label', where)
        value_cited = cite(item.value_cell, 'value', where, may_be_empty=True)
        for cid in [*item.note_cells, *([item.unit_cell] if item.unit_cell else [])]:cite(cid, 'note', where)
        for cond in item.conditions:cite(cond.label_cell, 'label', where);cite(cond.value_cell, 'condition', where)
        if item.value_cell in value_owner:result.error('VALUE_CELL_REUSED', where, [item.value_cell])
        value_owner[item.value_cell] = item.id
        if resource is None:result.error('UNKNOWN_RESOURCE', where);continue
        if not value_cited:continue
        try:c = catalog_for(resource)
        except Exception:continue
        if resource.type not in c.schemas:continue
        parts_list = [parse_pointer(p) for p in item.paths]
        for parts in parts_list:
            key = (item.resource, tuple(parts))
            if key in path_owner:result.error('PATH_CONFLICT', where)
            path_owner[key] = item.id
            for i, part in enumerate(parts[:-1]):
                if isinstance(part, int) and isinstance(parts[i + 1], str):
                    elements[(item.resource, tuple(parts[:i + 1]))].add(parts[i + 1])
            if parts[0] not in c.writable(resource.type) or c.readonly(resource.type, parts) or not c.at(resource.type, parts):
                result.error('INVALID_PATH', where)
        secret_path = any(sensitive(resource.type, parts) for parts in parts_list)
        if secret_path or item.state == 'SECRET_VALUE':secret_cells.add(item.value_cell)
        cell = book.cells.get(item.value_cell)
        empty = book.empty(item.value_cell);formula = cell is not None and cell['formula'] is not None
        state = item.state
        if state == 'BLANK':
            if not empty:result.error('NOT_BLANK', where, [item.value_cell])
        elif empty:result.error('EMPTY_VALUE_CELL', where, [item.value_cell])
        elif state == 'FORMULA':
            if not formula:result.error('NOT_A_FORMULA', where, [item.value_cell])
        elif formula:result.error('FORMULA_AS_' + state, where, [item.value_cell])
        elif state in ('UNDECIDED', 'NOT_APPLICABLE', 'DEFAULT'):
            if words.get(norm(book.text(item.value_cell))) != state:result.error('STATE_WORD_UNKNOWN', where, [item.value_cell])
        elif state == 'RESOURCE_REF':
            target = resources.get(item.ref)
            if target is None:result.error('UNKNOWN_REF_TARGET', where)
            elif target.name_cell is None or label_norm(book.text(target.name_cell)) != label_norm(book.text(item.value_cell)):
                result.error('REF_NAME_MISMATCH', where, [item.value_cell])
        elif state == 'SECRET_REF':
            if not re.match(r'^(secret|ssm)://.+', book.text(item.value_cell).strip()):result.error('NOT_A_SECRET_REFERENCE', where, [item.value_cell])
        if secret_path and state in ('LITERAL', 'DEFAULT', 'RESOURCE_REF'):result.error('SENSITIVE_PATH_NEEDS_SECRET_STATE', where, [item.value_cell])
        if cell is not None and cell['strike']:result.warn('STRUCK_THROUGH_VALUE', where, [item.value_cell])
        if book.sheet_of(item.value_cell)['state'] != 'visible':result.warn('HIDDEN_SHEET_VALUE', where, [item.value_cell])
        headers = book.headers.get(item.value_cell)
        if headers is not None and not set(item.label_cells) <= set(headers):result.warn('LABEL_NOT_A_STRUCTURE_HEADER', where, item.label_cells)
        status, entry = resolve_mapping(book, items_file, item, resource, dictionary)
        if status not in ('DICTIONARY', 'PROPOSED'):result.error(status, where);continue
        convert, value_map, units = rule(item, entry)
        if item.unit_cell and units and norm(book.text(item.unit_cell)) not in {norm(u) for u in units}:result.error('UNIT_MISMATCH', where, [item.unit_cell])
        if item.unit_cell and not units:result.warn('UNIT_NOT_DECLARED', where, [item.unit_cell])
        if state == 'LITERAL' and not empty and not formula:
            if secret_literal(book.text(item.value_cell)):result.error('SECRET_LIKE_LITERAL', where, [item.value_cell]);secret_cells.add(item.value_cell);continue
            try:value = convert_value(book, item.value_cell, convert, value_map)
            except ValueError as exc:result.error(str(exc), where, [item.value_cell]);continue
            if cell['type'] == 'number' and cell['number_format'] != 'General' and convert == 'string':
                result.warn('NUMBER_FORMAT_REVIEW', where, [item.value_cell])
            for parts in parts_list:
                try:c.shape(resource.type, parts, value)
                except ValueError:result.error('SCHEMA_TYPE_MISMATCH', where, [item.value_cell])
    for collection, how in ((items_file.extensions, 'extension'), (items_file.unmapped, 'unmapped')):
        for kept in collection:
            for ref in kept.cells:cite_range(ref, how, kept.id)
            if set(kept.resources) - set(resources):result.error('UNKNOWN_RESOURCE', kept.id)
            if kept.sensitive:secret_cells.update(c for ref in kept.cells for c in book.expand(ref))
    for n, excluded in enumerate(items_file.excluded):
        for ref in excluded.cells:cite_range(ref, 'excluded', f'excluded[{n}]')
    arrays = defaultdict(set)
    for (rid, parts) in path_owner:
        for i, part in enumerate(parts):
            if isinstance(part, int):arrays[(rid, parts[:i])].add(part)
    for (rid, prefix), indexes in arrays.items():
        if indexes != set(range(len(indexes))):result.error('ARRAY_GAP', rid)
    # An element needs every member its schema requires, e.g. a Tag's Key beside its Value.
    for (rid, prefix), members in elements.items():
        resource = resources[rid]
        try:c = catalog_for(resource)
        except Exception:continue
        if resource.type not in c.schemas:continue
        nodes = c.at(resource.type, list(prefix))
        requirements = [set(b['required']) for n in nodes for b in c.branches(resource.type, n) if isinstance(b.get('required'), list)]
        if requirements and not any(r <= members for r in requirements):
            result.error('INCOMPLETE_ELEMENT', f"{rid}{''.join('/' + str(x) for x in prefix)}")
    covered_by_header = set()
    for cid, how in referenced.items():
        # A header is accounted for once any cell under it is; excluded cells do not lend coverage.
        if how - {'excluded'}:covered_by_header.update(book.headers.get(cid, []))
    uncovered = [cid for cid in book.nonempty() if cid not in referenced and cid not in covered_by_header]
    if uncovered:result.error('UNCOVERED_CELLS', '', uncovered)
    for cid in book.nonempty():
        if secret_literal(book.text(cid)):secret_cells.add(cid)
    # Agent-written text must not repeat a secret cell's value.
    secrets = [book.text(c) for c in secret_cells if len(book.text(c)) >= 4]
    written = [items_file.author.actor, items_file.author.model, *all_ids,
               *(i.reason for i in items_file.items), *(e.reason for e in items_file.extensions),
               *(e.follow_up for e in items_file.extensions), *(u.reason for u in items_file.unmapped),
               *(u.follow_up for u in items_file.unmapped), *(x.reason for x in items_file.excluded),
               *(json.dumps(i.mapping.proposal.value_map, ensure_ascii=False) for i in items_file.items if i.mapping.proposal)]
    if any(s in text for s in secrets for text in written) or any(secret_literal(t) for t in written):result.error('SECRET_IN_AGENT_TEXT')
    result.referenced = referenced;result.header_covered = covered_by_header - set(referenced)
    result.secret_cells = secret_cells
    return result


def check_report(result):
    return {'status': 'FAIL' if result.errors else 'PASS', 'errors': result.errors, 'warnings': result.warnings,
            'error_counts': dict(sorted(Counter(e['code'] for e in result.errors).items()))}


def dump(value):return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def items_sha(raw):return sha(raw)


def build(book, items_raw, dictionary_raw, base_raw, *, review_raw=None, source_raw_before=None, source_raw_after=None):
    """Return {file name: bytes} and the summary. Raises InputError on invalid inputs."""
    from importlib.metadata import PackageNotFoundError, version
    from .document_catalog import catalog
    from .document_normalize import parse
    from .document_v11 import SchemaInput
    items_file = ItemsFile.model_validate_json(items_raw)
    dictionary, dictionary_sha = load_dictionary(dictionary_raw)
    base = parse(base_raw)
    if not isinstance(base, dict) or base.get('schema_version') != '1.1':raise InputError('base input must be a 1.1 document')
    regions = sorted({e['region'] for e in base.get('environments', []) if isinstance(e, dict) and 'region' in e})
    if not regions:raise InputError('base input needs environments with regions')
    result = check(book, items_file, dictionary, region=regions[0])
    if result.errors:raise InputError('ITEMS_INVALID: run check and fix the reported codes')
    for extra in regions[1:]:
        again = check(book, items_file, dictionary, region=extra)
        if again.errors:raise InputError('ITEMS_INVALID_FOR_REGION: ' + extra)
    review_state = 'MISSING'
    if review_raw is not None:
        review = Review.model_validate_json(review_raw)
        review_state = 'STALE' if review.items_sha256 != sha(items_raw) else review.decision.upper()
    source_state = 'NOT_PROVIDED'
    if source_raw_before is not None:
        if sha(source_raw_before) != book.source.get('sha256'):raise InputError('SOURCE_MISMATCH: original workbook differs from the ARP extraction source')
        source_state = 'VERIFIED_UNCHANGED' if sha(source_raw_after) == sha(source_raw_before) else 'CHANGED_DURING_RUN'
    resources = {r.id: r for r in items_file.resources}
    secret = result.secret_cells
    sheet_sources = {}

    def source_id(cid):
        sheet = book.sheet_of(cid)
        sheet_sources.setdefault(sheet['number'], {'id': f"xs-{sheet['number']}", 'title': sheet['name'],
                                                    'locator': f"{book.document}#{sheet['name']}"})
        return f"xs-{sheet['number']}"

    def shown(cid):
        if cid in secret:return REDACTED
        return book.text(cid)

    def cell_view(cid):
        cell = book.cells.get(cid)
        view = {**book.locate(cid), 'text': shown(cid) if cell else ''}
        if cell is not None:
            if cell['formula'] is not None:view['formula'] = REDACTED if cid in secret else cell['formula']
            if cell['type'] not in (None, 'string'):view['type'] = cell['type']
            if cell['number_format'] != 'General':view['number_format'] = cell['number_format']
        view['sheet_state'] = book.sheet_of(cid)['state']
        return view

    leaves = defaultdict(list);rows = [];trace = []
    for item in items_file.items:
        resource = resources[item.resource]
        status, entry = resolve_mapping(book, items_file, item, resource, dictionary)
        convert, value_map, _ = rule(item, entry)
        outcome, reason_code, leaf = 'WRITTEN', None, None
        if status == 'PROPOSED':outcome, reason_code = 'NOT_WRITTEN', 'MAPPING_NOT_APPROVED'
        elif item.state in NOT_WRITTEN:outcome, reason_code = 'NOT_WRITTEN', NOT_WRITTEN[item.state]
        else:
            text = book.text(item.value_cell)
            leaf = {'LITERAL': lambda: {'mode': 'LITERAL', 'value': convert_value(book, item.value_cell, convert, value_map)},
                    'UNDECIDED': lambda: {'status': 'UNDECIDED'},
                    'NOT_APPLICABLE': lambda: {'status': 'NOT_APPLICABLE'},
                    'DEFAULT': lambda: {'mode': 'DEFAULT'},
                    'RESOURCE_REF': lambda: {'mode': 'RESOURCE_REF', 'ref': item.ref},
                    'SECRET_REF': lambda: {'mode': 'SECRET_REF', 'classification': 'SECRET', 'ref': text.strip()}}[item.state]()
            for path in item.paths:
                parts = parse_pointer(path)
                leaves[(item.resource, parts[0])].append((parts[1:], leaf, item))
        sid = source_id(item.value_cell)
        written_ids = sorted({f'{item.resource}.{parse_pointer(p)[0]}' for p in item.paths}) if outcome == 'WRITTEN' else []
        rows.append({'item_id': item.id, 'resource_id': item.resource, 'resource_type': resource.type,
                     'service': catalog(regions[0]).services.get(resource.type), 'paths': item.paths,
                     'semantic_keys': [f'{item.resource}#{p}' for p in item.paths], 'state': item.state,
                     'mapping': {'status': 'DICTIONARY_APPROVED' if status == 'DICTIONARY' else 'PROPOSED_NOT_APPROVED',
                                 'entry_id': entry.id if entry else None, 'convert': convert},
                     'outcome': outcome, 'reason_code': reason_code, 'generated_item_ids': written_ids,
                     'converted_value': None if leaf is None or 'value' not in leaf or item.value_cell in secret else leaf['value'],
                     'label': ' / '.join(shown(c) for c in item.label_cells), 'label_cells': [cell_view(c) for c in item.label_cells],
                     'value_cell': cell_view(item.value_cell), 'unit_cell': cell_view(item.unit_cell) if item.unit_cell else None,
                     'note_cells': [cell_view(c) for c in item.note_cells],
                     'conditions': [{'label': cell_view(c.label_cell), 'value': cell_view(c.value_cell)} for c in item.conditions],
                     'reason': item.reason, 'source_id': sid})
        snapshot = {'setting_id': f'ext:{item.id}', 'kind': 'CFN', 'status': item.state,
                    'verification_status': rows[-1]['mapping']['status'], 'label': rows[-1]['label'],
                    'value': rows[-1]['value_cell']['text'], **({'formula': rows[-1]['value_cell']['formula']} if 'formula' in rows[-1]['value_cell'] else {}),
                    'paths': item.paths}
        trace.append({'setting_id': f'ext:{item.id}', 'kind': 'CFN', 'source_snapshot': snapshot, 'item_ids': written_ids,
                      'source_pointer': f"{book.document}#{book.sheet_of(item.value_cell)['name']}!{book.locate(item.value_cell)['address']}",
                      **({} if written_ids else {'exclusion_reason': reason_code})})
    retained = []
    for kind, collection in (('EXTENSION', items_file.extensions), ('UNMAPPED', items_file.unmapped)):
        for kept in collection:
            cells = [c for ref in kept.cells for c in book.expand(ref)]
            record = {'id': kept.id, 'kind': kind, 'category': kept.category, 'resources': kept.resources,
                      'cells': [cell_view(c) for c in cells], 'reason': kept.reason, 'follow_up': kept.follow_up}
            retained.append(record)
            first = cells[0] if cells else None
            trace.append({'setting_id': f'ext:{kept.id}', 'kind': 'APP' if kind == 'EXTENSION' else 'CFN',
                          'source_snapshot': {'setting_id': f'ext:{kept.id}', 'kind': 'APP' if kind == 'EXTENSION' else 'CFN',
                                              'status': kind, 'verification_status': kept.category,
                                              'texts': [v['text'] for v in record['cells']]},
                          'item_ids': [],
                          'source_pointer': f"{book.document}#{book.sheet_of(first)['name']}!{book.locate(first)['address']}" if first else book.document,
                          **({} if kind == 'EXTENSION' else {'exclusion_reason': f'UNMAPPED:{kept.category}'})})
    excluded = [{'cells': [cell_view(c) for ref in x.cells for c in book.expand(ref)], 'reason': x.reason} for x in items_file.excluded]

    def nest(entries):
        """Settings for one top-level property from (sub-path, leaf) pairs."""
        if len(entries) == 1 and not entries[0][0]:return dict(entries[0][1])
        if any(not sub for sub, _, _ in entries):raise InputError('PATH_CONFLICT: a value and its members are both given')
        root = None
        def container(key):return [] if isinstance(key, int) else {}
        literal = all(leaf.get('mode') == 'LITERAL' for _, leaf, _ in entries)
        for sub, leaf, _ in entries:
            if root is None:root = container(sub[0])
            node = root
            for i, key in enumerate(sub):
                last = i == len(sub) - 1
                value = (leaf['value'] if literal else ({'$design': leaf} if leaf.get('mode') != 'LITERAL' else leaf['value'])) if last else None
                if isinstance(node, list):
                    if not isinstance(key, int):raise InputError('PATH_CONFLICT')
                    while len(node) <= key:node.append(None)
                    if last:node[key] = value
                    else:
                        if node[key] is None:node[key] = container(sub[i + 1])
                        node = node[key]
                else:
                    if isinstance(key, int):raise InputError('PATH_CONFLICT')
                    if last:node[key] = value
                    else:node = node.setdefault(key, container(sub[i + 1]))
        return {'mode': 'LITERAL' if literal else 'COMPOSITE', 'value': root}

    design = json.loads(json.dumps(base))
    base_ids = {r['id'] for r in design.get('resources', [])}
    if base_ids & set(resources):raise InputError('base input already declares a resource ID used by the sheet')
    new_resources = []
    for r in items_file.resources:
        settings = {}
        for (rid, top), entries in sorted(((k, v) for k, v in leaves.items() if k[0] == r.id), key=lambda kv: kv[0][1]):
            setting = nest(entries)
            cells = sorted({e[2].value_cell for e in entries}, key=lambda c: (book.sheet_of(c)['number'], c))
            setting['rationale'] = '外部シート ' + '、'.join(f"{book.sheet_of(c)['name']}!{book.locate(c)['address']}" for c in cells)
            setting['sources'] = sorted({source_id(c) for c in cells})
            settings[top] = setting
        cited = [c for c in [r.name_cell, *r.evidence_cells] if c]
        resource = {'id': r.id, 'name': book.text(r.name_cell) if r.name_cell and r.name_cell not in secret else r.id,
                    'type': r.type, 'settings': settings,
                    'rationale': '外部シート ' + '、'.join(f"{book.sheet_of(c)['name']}!{book.locate(c)['address']}" for c in cited) if cited else '外部シート',
                    'sources': sorted({source_id(c) for c in cited})}
        if r.region:resource['region'] = r.region
        new_resources.append(resource)
    design['resources'] = [*design.get('resources', []), *new_resources]
    known_sources = {s['id'] for s in design.get('sources', [])}
    design['sources'] = [*design.get('sources', []), *[s for n, s in sorted(sheet_sources.items()) if s['id'] not in known_sources]]
    try:SchemaInput.model_validate(design)
    except ValidationError as exc:
        raise InputError('GENERATED_INPUT_INVALID: ' + ', '.join(sorted({e['type'] for e in exc.errors(include_input=False, include_context=False)}))) from None

    outcome_counts = Counter()
    by_sheet, by_type, by_service, by_state = (defaultdict(Counter) for _ in range(4))
    for row in rows:
        key = 'MAPPED' if row['outcome'] == 'WRITTEN' else 'PROPOSED' if row['reason_code'] == 'MAPPING_NOT_APPROVED' else 'NEEDS_CONFIRMATION'
        outcome_counts[key] += 1
        by_sheet[row['value_cell']['sheet']][key] += 1;by_type[row['resource_type']][key] += 1
        by_service[row['service']][key] += 1;by_state[row['state']][key] += 1
    for record in retained:
        key = 'EXTENSION' if record['kind'] == 'EXTENSION' else {'AMBIGUOUS': 'AMBIGUOUS', 'UNREADABLE': 'UNREADABLE'}.get(record['category'], 'UNMAPPED')
        outcome_counts[key] += 1
        for sheet in sorted({c['sheet'] for c in record['cells']}) or ['(シート外)']:by_sheet[sheet][key] += 1
        for rid in record['resources']:
            by_type[resources[rid].type][key] += 1;by_service[catalog(regions[0]).services.get(resources[rid].type)][key] += 1
    outcome_counts['EXCLUDED'] = len(excluded)
    resource_status = {}
    for r in items_file.resources:
        mine = [x for x in rows if x['resource_id'] == r.id]
        open_ = [x for x in rows if x['resource_id'] == r.id and x['outcome'] != 'WRITTEN'] + [x for x in retained if r.id in x['resources'] and x['kind'] == 'UNMAPPED']
        resource_status[r.id] = 'NOT_MAPPED' if not any(x['outcome'] == 'WRITTEN' for x in mine) else 'PARTIAL' if open_ else 'MAPPED'
    reasons = []
    if review_state != 'ACCEPTED':reasons.append(f'ITEMS_REVIEW_{review_state}')
    for key in ('PROPOSED', 'NEEDS_CONFIRMATION', 'UNMAPPED', 'AMBIGUOUS', 'UNREADABLE'):
        if outcome_counts.get(key):reasons.append(f'{key}:{outcome_counts[key]}')
    if source_state == 'CHANGED_DURING_RUN':reasons.append('SOURCE_CHANGED_DURING_RUN')
    import_status = 'INCOMPLETE' if reasons else 'COMPLETE'
    # The project file is the version source of record, as in schema_bootstrap; installed metadata can be stale.
    project = Path(__file__).resolve().parents[2] / 'pyproject.toml'
    if project.exists():
        import tomllib
        tool_version = tomllib.loads(project.read_text(encoding='utf-8'))['project']['version']
    else:
        try:tool_version = version('aws-design-sheet')
        except PackageNotFoundError:tool_version = 'unknown'
    versions = {
        'tool': {'name': 'aws-design-sheet', 'version': tool_version, 'external_contract': CONTRACT_VERSION},
        'arp': {'parser': book.parser, 'extraction_schema': EXTRACTION_SCHEMA, 'extraction_sha256': book.extraction_sha256,
                'structure_content_hash': book.structure_content_hash, 'structure_review': book.structure_review},
        'source': {'document': book.document, 'path': book.source.get('path'), 'sha256': book.source.get('sha256'),
                   'state': source_state, 'sheet_version': book.text(items_file.sheet_version_cell) if items_file.sheet_version_cell else None},
        'items': {'sha256': sha(items_raw), 'author': items_file.author.model_dump(), 'review': review_state},
        'dictionary': {'sha256': dictionary_sha, 'entries': len(dictionary.entries)},
        'schemas': [{'region': reg, 'zip_sha256': catalog(reg).manifest['zip_sha256'], 'retrieved_at': catalog(reg).manifest['retrieved_at']}
                    for reg in sorted({*regions, *(r.region for r in items_file.resources if r.region)})],
    }
    covered = Counter()
    for cid in book.nonempty():
        hows = result.referenced.get(cid)
        covered[sorted(hows)[0] if hows else 'header'] += 1
    coverage = {
        'import_status': import_status, 'reasons': reasons, 'outcome_counts': dict(sorted(outcome_counts.items())),
        'by_sheet': {k: dict(sorted(v.items())) for k, v in sorted(by_sheet.items())},
        'by_resource_type': {k: dict(sorted(v.items())) for k, v in sorted(by_type.items())},
        'by_service': {str(k): dict(sorted(v.items())) for k, v in sorted(by_service.items(), key=lambda kv: str(kv[0]))},
        'by_state': {k: dict(sorted(v.items())) for k, v in sorted(by_state.items())},
        'resources': resource_status,
        'cells': {'nonempty': len(book.nonempty()), 'covered_by': dict(sorted(covered.items()))},
        'sheets': book.sheets,
        'follow_ups': [{'item_id': r['item_id'], 'reason_code': r['reason_code'], 'cell': r['value_cell']['cell']} for r in rows if r['outcome'] != 'WRITTEN']
                      + [{'item_id': x['id'], 'reason_code': f"{x['kind']}:{x['category']}", 'follow_up': x['follow_up']} for x in retained if x['kind'] == 'UNMAPPED'],
        'unchecked_scope': [{'feature': f, 'state': 'NOT_EXTRACTED_BY_ARP'} for f in UNEXTRACTED],
        'warnings': result.warnings,
        'versions': versions,
        'notes': ['import_status は抽出項目の変換状態だけを表します。設計の承認・網羅・AWS上の妥当性は表しません。',
                  'unchecked_scope の情報は原本から読み取っていません。入力規則の選択肢などは別途確認してください。'],
    }
    mapping = {'contract_version': CONTRACT_VERSION, 'document': book.document, 'rows': rows, 'retained': retained, 'excluded': excluded}
    files = {'input.json': dump(design), 'source-trace.json': dump({'rows': trace}),
             'external-mapping.json': dump(mapping), 'external-coverage.json': dump(coverage)}
    files['external-trace.xlsx'] = trace_workbook(mapping, coverage)
    summary = {'import_status': import_status, 'reasons': reasons, 'outcome_counts': coverage['outcome_counts'],
               'files': sorted(files)}
    return files, summary


def trace_workbook(mapping, coverage):
    """Readable companion of the JSON outputs; cell text is stored as text, never as formulas."""
    from io import BytesIO
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font
    book = Workbook();first = True

    def sheet(title, header, rows):
        nonlocal first
        ws = book.active if first else book.create_sheet(title)
        ws.title = title;first = False
        ws.append(header)
        for cell in ws[1]:cell.font = Font(bold=True)
        for row in rows:
            ws.append([None] * len(row))
            for col, value in enumerate(row, 1):
                cell = ws.cell(ws.max_row, col)
                text = value if value is None or isinstance(value, (int, float, bool)) else str(value)
                if isinstance(text, str) and len(text) > 32767:text = text[:32700] + '…(全文はJSON)'
                cell.value = text
                if isinstance(text, str):cell.data_type = 's'
                cell.alignment = Alignment(wrap_text=True, vertical='top')
        ws.freeze_panes = 'A2';ws.auto_filter.ref = ws.dimensions
    loc = lambda v: f"{v['sheet']}!{v['address']}" if v else ''
    sheet('対応表', ['項目ID', '原本位置', 'ラベル', '原本の値', '式', '状態', 'リソース', 'リソース型', 'プロパティパス',
                  '対応状態', '辞書ID', '変換後の値', '出力', '理由コード', '単位', '備考', '条件', '根拠'],
          [[r['item_id'], loc(r['value_cell']), r['label'], r['value_cell']['text'], r['value_cell'].get('formula', ''), r['state'],
            r['resource_id'], r['resource_type'], '\n'.join(r['paths']), r['mapping']['status'], r['mapping']['entry_id'] or '',
            '' if r['converted_value'] is None else json.dumps(r['converted_value'], ensure_ascii=False), r['outcome'], r['reason_code'] or '',
            r['unit_cell']['text'] if r['unit_cell'] else '', '\n'.join(n['text'] for n in r['note_cells']),
            '\n'.join(f"{c['label']['text']}={c['value']['text']}" for c in r['conditions']), r['reason']] for r in mapping['rows']])
    sheet('未対応・要確認', ['ID', '区分', '分類', '原本位置', '原文', 'リソース', '理由', '後続確認'],
          [[r['item_id'], '変換保留', r['reason_code'], loc(r['value_cell']), r['value_cell']['text'], r['resource_id'], r['reason'], '']
           for r in mapping['rows'] if r['outcome'] != 'WRITTEN'] +
          [[x['id'], '未対応', x['category'], '\n'.join(loc(c) for c in x['cells']), '\n'.join(c['text'] for c in x['cells']),
            ', '.join(x['resources']), x['reason'], x['follow_up']] for x in mapping['retained'] if x['kind'] == 'UNMAPPED'])
    sheet('拡張項目', ['ID', '分類', '原本位置', '原文', 'リソース', '理由'],
          [[x['id'], x['category'], '\n'.join(loc(c) for c in x['cells']), '\n'.join(c['text'] for c in x['cells']),
            ', '.join(x['resources']), x['reason']] for x in mapping['retained'] if x['kind'] == 'EXTENSION'])
    sheet('除外', ['原本位置', '原文', '理由'],
          [['\n'.join(loc(c) for c in x['cells']), '\n'.join(c['text'] for c in x['cells']), x['reason']] for x in mapping['excluded']])
    sheet('対応範囲', ['区分', '対象', '件数の内訳'],
          [['全体', coverage['import_status'], json.dumps(coverage['outcome_counts'], ensure_ascii=False)],
           *[['理由', r, ''] for r in coverage['reasons']],
           *[['シート', k, json.dumps(v, ensure_ascii=False)] for k, v in coverage['by_sheet'].items()],
           *[['リソース型', k, json.dumps(v, ensure_ascii=False)] for k, v in coverage['by_resource_type'].items()],
           *[['サービス', k, json.dumps(v, ensure_ascii=False)] for k, v in coverage['by_service'].items()],
           *[['状態', k, json.dumps(v, ensure_ascii=False)] for k, v in coverage['by_state'].items()],
           *[['リソース', k, v] for k, v in coverage['resources'].items()],
           *[['未検査', u['feature'], u['state']] for u in coverage['unchecked_scope']],
           *[['注記', n, ''] for n in coverage['notes']]])
    sheet('版情報', ['対象', '値'], [[k, json.dumps(v, ensure_ascii=False)] for k, v in coverage['versions'].items()])
    out = BytesIO();book.save(out);book.close()
    return out.getvalue()


def approve(book, items_file, dictionary, approver, selected=None, *, now=None):
    """Turn proposals into dictionary entries. Only a person named by the user approves."""
    from .document_catalog import catalog
    if not approver.strip():raise InputError('APPROVER_REQUIRED')
    resources = {r.id: r for r in items_file.resources}
    known = {canonical(e.resource_type, e.paths, e.convert, e.value_map, e.units, [w.model_dump() for w in e.when]): e for e in dictionary.entries}
    entries = list(dictionary.entries);added, extended = [], []
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    wanted = [i for i in items_file.items if i.mapping.proposal and (selected is None or i.id in selected)]
    if selected is not None and set(selected) - {i.id for i in wanted}:raise InputError('UNKNOWN_PROPOSAL')
    for item in wanted:
        p = item.mapping.proposal;resource = resources[item.resource]
        when = proposal_when(book, item);label = label_text(book, item)
        key = canonical(resource.type, item.paths, p.convert, p.value_map, p.units, when)
        if key in known:
            entry = known[key]
            if label_norm(label) not in {label_norm(x) for x in entry.labels}:
                updated = entry.model_copy(update={'labels': [*entry.labels, label]})
                entries[entries.index(entry)] = updated;known[key] = updated;extended.append(entry.id)
            continue
        slug = re.sub(r'[^a-z0-9]+', '-', f"{resource.type.split('::', 1)[-1]}-{pattern_of(item.paths[0])}".lower()).strip('-')[:110]
        entry = Entry(id=f"{slug}-{sha(json.dumps(key, ensure_ascii=False).encode())[:8]}",
                      resource_type=resource.type, labels=[label], paths=sorted({pattern_of(x) for x in item.paths}),
                      convert=p.convert, value_map={norm(k): v for k, v in p.value_map.items()}, units=sorted({norm(u) for u in p.units}),
                      when=[When(label=w['label'], values=w['values']) for w in when], approved_by=approver.strip(), approved_at=stamp,
                      evidence=EntryEvidence(document=book.document, extraction_sha256=book.extraction_sha256, item_id=item.id,
                                             label_cells=item.label_cells))
        entries.append(entry);known[key] = entry;added.append(entry.id)
    result = Dictionary(schema_version='1', state_words=dictionary.state_words, entries=sorted(entries, key=lambda e: e.id))
    return result, {'added': added, 'labels_added_to': sorted(set(extended))}


def view(book, sheet=None):
    """Compact agent view: one line per extracted cell with role, headers and value."""
    lines = []
    for s in book.sheets:
        if sheet not in (None, s['name'], str(s['number'])):continue
        lines.append(f"## s{s['number']} {s['name']} ({s['state']})")
        for cid, cell in book.cells.items():
            if cell['sheet_number'] != s['number']:continue
            headers = ' / '.join(f'{h}={book.text(h)}' for h in book.headers.get(cid, []))
            extra = f" formula={cell['formula']}" if cell['formula'] is not None else ''
            extra += f" format={cell['number_format']}" if cell['number_format'] != 'General' else ''
            extra += ' struck' if cell['strike'] else ''
            lines.append(f"{cid}\t{book.roles.get(cid, '-')}\t[{headers}]\t{json.dumps(cell['value'], ensure_ascii=False)}{extra}")
        merged = sorted({v for v in book.merged.values() if book.sheet_of(v)['number'] == s['number']})
        if merged:lines.append('merged anchors: ' + ', '.join(merged))
    return '\n'.join(lines) + '\n'


def open_book(args):
    return Sheetbook(Path(args.extraction).read_bytes(), Path(args.structure).read_bytes(),
                     Path(args.document).read_bytes() if args.document else None)


def write_new(path, data):
    path = Path(path)
    if path.exists():raise InputError('output already exists; use a fresh path')
    path.write_bytes(data)


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design-external', description='External design sheets parsed by ARP4 to 1.1 input')
    sub = parser.add_subparsers(dest='command', required=True)

    def arp_args(p):
        p.add_argument('--extraction', required=True, help='ARP4 extraction.json')
        p.add_argument('--structure', required=True, help='ARP4 structure view with an accepted review')
        p.add_argument('--document', help='ARP4 document.yml, checked against extraction and structure')
    p = sub.add_parser('schema', help='print the JSON Schema of an agent-facing contract')
    p.add_argument('--kind', choices=['items', 'dictionary', 'review'], default='items')
    p = sub.add_parser('view', help='compact cell view for the worker agent');arp_args(p);p.add_argument('--sheet')
    p = sub.add_parser('check', help='validate an items file');arp_args(p)
    p.add_argument('--items', required=True);p.add_argument('--dictionary');p.add_argument('--region')
    p = sub.add_parser('review', help='record an independent review of an items file');arp_args(p)
    p.add_argument('--items', required=True);p.add_argument('--dictionary');p.add_argument('--region')
    p.add_argument('--decision', choices=['accepted', 'rejected'], required=True)
    p.add_argument('--actor', required=True);p.add_argument('--reason', required=True);p.add_argument('--output', required=True)
    p = sub.add_parser('approve', help='add proposed mappings to the dictionary; approver must be a person the user names');arp_args(p)
    p.add_argument('--items', required=True);p.add_argument('--dictionary');p.add_argument('--output', required=True)
    p.add_argument('--approver', required=True)
    group = p.add_mutually_exclusive_group(required=True);group.add_argument('--all', action='store_true');group.add_argument('--item', action='append')
    p = sub.add_parser('build', help='write 1.1 input, source trace, mapping table and coverage');arp_args(p)
    p.add_argument('--items', required=True);p.add_argument('--dictionary');p.add_argument('--review')
    p.add_argument('--base', required=True, help='1.1 frame with system and environments (resources optional)')
    p.add_argument('--source', help='original workbook; only its hash is read, before and after the run')
    p.add_argument('--output', required=True, help='fresh output directory')
    args = parser.parse_args(argv)
    try:
        if args.command == 'schema':
            model = {'items': ItemsFile, 'dictionary': Dictionary, 'review': Review}[args.kind]
            print(json.dumps(model.model_json_schema(), ensure_ascii=False, indent=2));return 0
        book = open_book(args)
        if args.command == 'view':
            sys.stdout.buffer.write(view(book, args.sheet).encode('utf-8'));return 0
        items_raw = Path(args.items).read_bytes();items_file = ItemsFile.model_validate_json(items_raw)
        dictionary, _ = load_dictionary(Path(args.dictionary).read_bytes() if args.dictionary else None)
        if args.command == 'check':
            report = check_report(check(book, items_file, dictionary, region=args.region))
            print(json.dumps(report, ensure_ascii=False, indent=2));return 0 if report['status'] == 'PASS' else 2
        if args.command == 'review':
            if args.actor.strip() == items_file.author.actor.strip():raise InputError('REVIEWER_IS_AUTHOR: use an independent reviewer')
            report = check_report(check(book, items_file, dictionary, region=args.region))
            if args.decision == 'accepted' and report['status'] != 'PASS':raise InputError('CHECK_FAILED: an items file with errors cannot be accepted')
            review = Review(schema_version='1', items_sha256=sha(items_raw), decision=args.decision, actor=args.actor.strip(),
                            reason=args.reason, recorded_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
            write_new(args.output, dump(review.model_dump()))
            print(json.dumps({'review': args.decision, 'items_sha256': review.items_sha256}));return 0
        if args.command == 'approve':
            result = check(book, items_file, dictionary)
            if result.errors:raise InputError('CHECK_FAILED: fix the items file before approving its proposals')
            updated, changes = approve(book, items_file, dictionary, args.approver, None if args.all else args.item)
            write_new(args.output, dump(updated.model_dump(exclude_none=True)))
            print(json.dumps(changes, ensure_ascii=False));return 0
        output = Path(args.output)
        if output.exists():raise InputError('output directory already exists; use a fresh destination')
        before = Path(args.source).read_bytes() if args.source else None
        files, summary = build(book, items_raw, Path(args.dictionary).read_bytes() if args.dictionary else None,
                               Path(args.base).read_bytes(), review_raw=Path(args.review).read_bytes() if args.review else None,
                               source_raw_before=before, source_raw_after=Path(args.source).read_bytes() if args.source else None)
        output.mkdir(parents=True)
        for name, data in files.items():(output / name).write_bytes(data)
        print(json.dumps(summary, ensure_ascii=False));return 0 if summary['import_status'] == 'COMPLETE' else 3
    except ValidationError as exc:
        # Locations and error types only; input values could hold secrets.
        errors = [{'loc': [str(x) for x in e['loc']], 'type': e['type']} for e in exc.errors(include_input=False, include_context=False)]
        print(json.dumps({'status': 'ERROR', 'message': 'CONTRACT_INVALID', 'errors': errors}, ensure_ascii=False));return 2
    except (InputError, json.JSONDecodeError, OSError) as exc:
        message = str(exc) if isinstance(exc, InputError) else type(exc).__name__
        print(json.dumps({'status': 'ERROR', 'message': message}, ensure_ascii=False));return 2


if __name__ == '__main__':
    raise SystemExit(main())
