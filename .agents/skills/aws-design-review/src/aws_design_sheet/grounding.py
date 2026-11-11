"""Grounding: each value a design takes from a document is found where the design cites it.

For every decided literal setting (and each scalar leaf of a composite one), the citation is
followed into the ARP4 extraction of the approved source set: a locator `DOCUMENT_ID#s1-C5`
(or a range `s1-C5:D9`, several separated by commas) names cells, `DOCUMENT_ID#s1-d4` a
drawing by its text and alternative text, `DOCUMENT_ID#シート名` a sheet and a bare `DOCUMENT_ID`
the whole document. A node or edge read from an image (`DOCUMENT_ID#v:VISUAL/n:NODE`) holds no
words of the document, so a value cited to it is INTERPRETED. A value is GROUNDED when its normalised
text, number or boolean word is in the cited cells and NOT_FOUND when it is not: a cell
citation that does not hold its value fails. With only a sheet or document cited, the value is
FOUND_IN_DOCUMENT or NOT_FOUND_IN_DOCUMENT, both weak: a converted value (a port from a
protocol name, a flag from a word) cannot be matched as text, so it is reported, not failed.
A value whose cited cells do not hold it but whose setting explains how it was derived (a
`rationale`, such as a unit conversion or a word turned into a flag) is INTERPRETED: it does
not fail, and a person reviews it. Values imported through an external-sheet source trace are
TRACED (that import already binds each value to its cell), values a decision states without a
cited cell are DECISION, and a literal with no source at all is UNSOURCED. A link to a decision
does not excuse a setting from its own citations. The check reads no values into its report
beyond codes, pointers and cell IDs, and it judges citations only, never whether the value is
right.
"""
import re
import unicodedata

from .source_set import CITABLE, cell_texts, column

CELL = re.compile(r'^s(\d+)-([A-Z]{1,3})(\d+)(?::([A-Z]{1,3})(\d+))?$')
DRAWING = re.compile(r'^(?:s\d+-d\d+|a\d+)$')
VISION = re.compile(r'^v:[^/,\s]+/(?:n:[^/,\s]+|e:\d+)$')
TRUE_WORDS = {'true', 'yes', 'on', 'enable', 'enabled', '有効', '有', 'あり', '要', 'する', '使用', '使用する', '利用', '利用する', '○', '◯', '〇', 'はい'}
FALSE_WORDS = {'false', 'no', 'off', 'disable', 'disabled', '無効', '無', 'なし', '不要', 'しない', '使用しない', '利用しない', '×', '✕', 'いいえ'}
STRENGTH = {'GROUNDED': 5, 'TRACED': 5, 'DECISION': 4, 'INTERPRETED': 4, 'FOUND_IN_DOCUMENT': 3, 'NOT_FOUND_IN_DOCUMENT': 2, 'NOT_CHECKABLE': 1,
            'NOT_FOUND': 0, 'CITES_NOT_CURRENT': 0, 'UNSOURCED': 0}
FAILING = {'NOT_FOUND', 'CITES_NOT_CURRENT', 'UNSOURCED'}
WEAK = {'FOUND_IN_DOCUMENT', 'NOT_FOUND_IN_DOCUMENT', 'NOT_CHECKABLE'}
NUMBER = re.compile(r'(?<![\w.])-?\d{1,3}(?:,\d{3})+(?:\.\d+)?|-?\d+(?:\.\d+)?')


def norm(text):return re.sub(r'\s+', '', unicodedata.normalize('NFKC', str(text))).casefold()


def numbers(text):
    found = set()
    for m in NUMBER.finditer(unicodedata.normalize('NFKC', str(text))):
        try:found.add(float(m.group(0).replace(',', '')))
        except ValueError:pass
    return found


def words(text):return {w for w in re.split(r'[\s、,。/／()（）\[\]「」:：=]+', norm(text)) if w}


def found(value, texts):
    """Whether one scalar value appears in any of the texts."""
    if isinstance(value, bool):
        wanted = TRUE_WORDS if value else FALSE_WORDS
        return any(words(t) & wanted or norm(t).strip('.。') in wanted for t in texts)
    if isinstance(value, (int, float)):return any(float(value) in numbers(t) for t in texts)
    if isinstance(value, str):
        target = norm(value)
        return bool(target) and any(target in norm(t) for t in texts)
    return False


def leaves(value, pointer=''):
    """Scalar leaves of a composite value with their pointers below the setting; keys are structure, not claims."""
    if isinstance(value, dict):
        for key, child in value.items():yield from leaves(child, f"{pointer}/{str(key).replace('~', '~0').replace('/', '~1')}")
    elif isinstance(value, list):
        for i, child in enumerate(value):yield from leaves(child, f'{pointer}/{i}')
    elif value is not None:yield pointer, value


def expand(place):
    """Cell IDs a place names, or None when it is not a cell reference."""
    cells = []
    for part in place.split(','):
        m = CELL.match(part.strip())
        if not m:return None
        sheet, first_col, first_row, last_col, last_row = m.groups()
        if last_col is None:cells.append(f's{sheet}-{first_col}{first_row}');continue
        c1, c2 = sorted((column(first_col), column(last_col)));r1, r2 = sorted((int(first_row), int(last_row)))
        if (c2 - c1 + 1) * (r2 - r1 + 1) > 2000:return None
        from .external_sheet import letters
        cells += [f's{sheet}-{letters(c)}{r}' for c in range(c1, c2 + 1) for r in range(r1, r2 + 1)]
    return cells


class Library:
    """Cell texts of the ARP4 documents in an approved source set."""

    def __init__(self, documents=None, entries=None):
        self.entries = entries or {}
        self.cells = {d['document_id']: dict(cell_texts(d['extraction'])) for d in (documents or [])}
        from .diagram_ledger import element_texts
        # A drawing (`s1-d4`) holds its text and alternative text as a cell holds its value.
        self.drawings = {d['document_id']: dict(element_texts(d['extraction'])) for d in (documents or [])}
        self.sheets = {d['document_id']: {norm(s.get('name', '')): n for n, s in enumerate(d['extraction'].get('sheets', []), 1)} for d in (documents or [])}

    @classmethod
    def from_arp(cls, root, set_raw):
        from .source_set import load_approved, read_arp
        documents, _ = read_arp(root)
        return cls(documents, {e.document_id: e for e in load_approved(set_raw).documents})

    def judge(self, locator, values):
        """(status, detail) of one citation for the given scalar values."""
        document, _, place = str(locator).partition('#')
        entry = self.entries.get(document)
        if entry is None or document not in self.cells:return 'NOT_CHECKABLE', 'NOT_AN_ARP_DOCUMENT'
        if entry.status not in CITABLE:return 'CITES_NOT_CURRENT', entry.status
        parts = [p.strip() for p in place.split(',')] if place else []
        # What was read from an image holds no words of the document: a person reviews it.
        if parts and all(VISION.match(p) for p in parts):return 'INTERPRETED', 'VISION_READING'
        if parts and all(DRAWING.match(p) for p in parts):
            texts = [self.drawings.get(document, {}).get(p, '') for p in parts]
            return ('GROUNDED', ','.join(parts[:5])) if all(found(v, texts) for v in values) else ('NOT_FOUND', ','.join(parts[:5]))
        cells = expand(place) if place else None
        if cells is not None:
            texts = [self.cells[document][c] for c in cells if c in self.cells[document]]
            return ('GROUNDED', ','.join(cells[:5])) if all(found(v, texts) for v in values) else ('NOT_FOUND', ','.join(cells[:5]))
        sheet = self.sheets[document].get(norm(place)) if place else None
        where = f'{document}#{place}' if sheet else document
        texts = [t for c, t in self.cells[document].items() if sheet is None or c.startswith(f's{sheet}-')]
        return ('FOUND_IN_DOCUMENT', where) if all(found(v, texts) for v in values) else ('NOT_FOUND_IN_DOCUMENT', where)


def settings_of(design):
    """(pointer, resource, property, setting) for resource settings and environment overrides."""
    resources = [r for r in design.get('resources', []) if isinstance(r, dict)]
    by_id = {r.get('id'): r for r in resources}
    for i, r in enumerate(resources):
        for name, setting in (r.get('settings') or {}).items():
            yield f"/resources/{i}/settings/{name.replace('~', '~0').replace('/', '~1')}", r, name, setting
    for i, env in enumerate(design.get('environments', []) or []):
        for j, override in enumerate(env.get('overrides', []) or []):
            for name, setting in (override.get('settings') or {}).items():
                yield (f"/environments/{i}/overrides/{j}/settings/{name.replace('~', '~0').replace('/', '~1')}",
                       by_id.get(override.get('resource_id'), {'id': override.get('resource_id')}), name, setting)


def claimed(setting):
    """Scalar values a decided literal setting claims, or None for settings that claim no document value."""
    if not isinstance(setting, dict) or setting.get('status', 'DECIDED') != 'DECIDED':return None
    if setting.get('mode') == 'LITERAL' and setting.get('value') is not None and not isinstance(setting.get('value'), (dict, list)):return [setting['value']]
    if setting.get('mode') in ('LITERAL', 'COMPOSITE') and isinstance(setting.get('value'), (dict, list)):
        return list(composite_claims(setting['value'])) or None
    return None


def composite_claims(value):
    """Scalar leaves of a composite; an embedded `$design` setting claims what it would claim on its own, so a reference claims nothing."""
    if isinstance(value, dict) and set(value) == {'$design'}:yield from claimed(value['$design']) or []
    elif isinstance(value, dict):
        for child in value.values():yield from composite_claims(child)
    elif isinstance(value, list):
        for child in value:yield from composite_claims(child)
    elif value is not None:yield value


# One sentence on the settings of this many different properties says how none of them was derived. (Careful authors
# repeat a derivation, "「有効」を真偽値に変換", over about ten properties; a stock sentence covered forty and more.)
STOCK_PROPERTIES = 20


def said(setting):
    """A setting's rationale with its spaces folded, so that one sentence is counted once."""
    return ' '.join(str(setting.get('rationale') or '').split()) if isinstance(setting, dict) else ''


def stock_rationales(design):
    """Rationales that decided settings of STOCK_PROPERTIES or more different properties share, most used first:
    such a sentence hides the derivations a person must review, and it explains no value its cells do not hold."""
    found = {}
    for pointer, _, name, setting in settings_of(design):
        text = said(setting)
        if not text or setting.get('status', 'DECIDED') != 'DECIDED':continue
        row = found.setdefault(text, {'code': 'RATIONALE_REPEATED', 'rationale': text, 'settings': 0, 'properties': set(), 'pointer': pointer})
        row['settings'] += 1;row['properties'].add(name)
    rows = [{**r, 'properties': len(r['properties'])} for r in found.values() if len(r['properties']) >= STOCK_PROPERTIES]
    return sorted(rows, key=lambda r: -r['settings'])


def ground(design, library=None, trace_rows=None):
    """A row per claimed setting, a count per status and the overall status (PASS, WARN or FAIL)."""
    library = library or Library()
    stock = {r['rationale'] for r in stock_rationales(design)}
    sources = {s.get('id'): s.get('locator', '') for s in design.get('sources', []) if isinstance(s, dict)}
    traced = {item for row in (trace_rows or []) for item in row.get('item_ids', [])}
    rows = []
    for pointer, resource, name, setting in settings_of(design):
        values = claimed(setting)
        if values is None:continue
        row = {'pointer': pointer, 'resource_id': resource.get('id'), 'property': name}
        if f"{resource.get('id')}.{name}" in traced:row.update(status='TRACED', detail='source-trace')
        elif setting.get('decision_ids') and not setting.get('sources'):row.update(status='DECISION', detail=','.join(setting['decision_ids']))
        else:
            cited = list(setting.get('sources') or [])
            level = 'SETTING'
            if not cited:cited, level = list(resource.get('sources') or []), 'RESOURCE'
            if not cited:row.update(status='UNSOURCED', detail='')
            else:
                judged = [(library.judge(sources.get(s, ''), values), s) for s in cited]
                (status, detail), source = max(judged, key=lambda j: STRENGTH[j[0][0]])
                # Cells that do not hold a value the setting explains deriving are an interpretation to review, not a failure.
                # Under a stock sentence it is still an interpretation (a draft is not failed for it), marked as resting on that sentence alone.
                if status == 'NOT_FOUND' and said(setting):status, detail = 'INTERPRETED', 'RATIONALE_REPEATED' if said(setting) in stock else detail
                # A resource-level citation of exact cells still grounds; a whole document cited for a resource is weak.
                row.update(status=status, detail=detail, source=source, level=level)
        rows.append(row)
    counts = {}
    for r in rows:counts[r['status']] = counts.get(r['status'], 0) + 1
    status = 'FAIL' if FAILING & set(counts) else 'WARN' if WEAK & set(counts) else 'PASS'
    return {'status': status, 'counts': dict(sorted(counts.items())), 'rows': rows}


# Settings AWS reads in UTC. A time copied as the documents write it in Japan time is wrong by nine hours, and the
# grounding finds it in its cell, so only this check sees it.
UTC_PROPERTIES = ('PreferredBackupWindow', 'PreferredMaintenanceWindow', 'SnapshotWindow', 'ScheduleExpression')
LOCAL_TIME = re.compile(r'日本時間|日本標準時|(?<![A-Za-z])JST(?![A-Za-z])')
SAYS_UTC = re.compile(r'(?<![A-Za-z])(?:UTC|GMT)(?![A-Za-z])|協定世界時')
CELL_HOUR = re.compile(r'(?<!\d)(\d{1,2})\s*(?:[:：]\s*\d{2}|時)')
VALUE_HOUR = re.compile(r'(?<!\d)(\d{1,2}):\d{2}')
CRON_HOUR = re.compile(r'cron\(\s*\S+\s+(\d{1,2})(?=\s)')


def utc_claims(name, setting):
    """(property, value) of the UTC settings a setting holds: itself, or keys inside its composite value. A schedule
    with a time zone beside it is in that zone, not UTC."""
    if not isinstance(setting, dict) or setting.get('status', 'DECIDED') != 'DECIDED':return
    value = setting.get('value')
    if name in UTC_PROPERTIES and isinstance(value, str):yield name, value
    def walk(node):
        if isinstance(node, dict):
            if set(node) == {'$design'}:
                return
            for key, child in node.items():
                if key in UTC_PROPERTIES and not any('timezone' in k.lower() for k in node):
                    leaf = child['$design'].get('value') if isinstance(child, dict) and set(child) == {'$design'} and isinstance(child['$design'], dict) else child
                    if isinstance(leaf, str):yield key, leaf
                yield from walk(child)
        elif isinstance(node, list):
            for child in node:yield from walk(child)
    if isinstance(value, (dict, list)):yield from walk(value)


def time_zone_findings(design, library):
    """UTC settings whose hour is the hour their cited cell writes, in a document that writes its times in Japan time."""
    sources = {s.get('id'): s.get('locator', '') for s in design.get('sources', []) if isinstance(s, dict)}
    local = {d: any(LOCAL_TIME.search(t) for t in cells.values()) for d, cells in library.cells.items()}
    rows = []
    for pointer, resource, name, setting in settings_of(design):
        zoned = any('timezone' in str(k).lower() and isinstance(s, dict) and s.get('status', 'DECIDED') == 'DECIDED' for k, s in (resource.get('settings') or {}).items())
        for prop, value in utc_claims(name, setting):
            if zoned and prop == 'ScheduleExpression':continue
            hours = {int(h) for h in VALUE_HOUR.findall(value)} | {int(h) for h in CRON_HOUR.findall(value)}
            for source in (setting.get('sources') or []) if isinstance(setting, dict) else []:
                document, _, place = str(sources.get(source, '')).partition('#')
                if not local.get(document) or not place:continue
                texts = [library.cells[document][c] for c in expand(place) or [] if c in library.cells[document]]
                if any(SAYS_UTC.search(t) for t in texts):continue
                if hours & {int(h) for t in texts for h in CELL_HOUR.findall(t)}:
                    rows.append({'pointer': pointer, 'resource_id': resource.get('id'), 'property': prop, 'code': 'TIME_ZONE_AS_WRITTEN', 'source': source});break
    return rows


def self_test(design, library=None, trace_rows=None):
    """Plant a value no document holds into one cited setting; grounding must stop finding it."""
    report = ground(design, library, trace_rows)
    target = next((r for r in report['rows'] if r['status'] == 'GROUNDED'), None) or next((r for r in report['rows'] if r['status'] == 'FOUND_IN_DOCUMENT'), None)
    if target is None:return {'status': 'SKIPPED', 'detail': 'NO_GROUNDED_VALUE'}
    import copy
    planted = copy.deepcopy(design)
    parts = target['pointer'].strip('/').split('/')
    node = planted
    for part in parts:node = node[int(part)] if isinstance(node, list) else node[part.replace('~1', '/').replace('~0', '~')]
    marker = 'zz-grounding-canary-7f3a9c'
    node['mode'], node['value'] = 'LITERAL', marker
    # A rationale turns a value its cells do not hold into an interpretation to review; the planted value has none.
    node.pop('rationale', None)
    again = next(r for r in ground(planted, library, trace_rows)['rows'] if r['pointer'] == target['pointer'])
    return {'status': 'PASS' if again['status'] in ('NOT_FOUND', 'NOT_FOUND_IN_DOCUMENT') else 'FAIL', 'detail': f"{target['pointer']} → {again['status']}"}
