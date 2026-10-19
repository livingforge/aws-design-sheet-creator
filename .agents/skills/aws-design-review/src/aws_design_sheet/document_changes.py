"""Excel proposals to reviewed input changes. The workbook never writes the input directly.

`propose` reads only the dedicated edit columns of generated 1.1 service sheets and
writes a change proposal. `apply` needs an approver, writes a new input file and
records every applied change in the input's change_log.
"""
import argparse
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

import sys

from pydantic import Field, JsonValue, ValidationError

from .models import StrictModel

ID = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_-]{0,63}$')]
UNDECIDED_WORDS = ('未決定', 'UNDECIDED')
SCOPES = {'共通': 'COMMON', 'COMMON': 'COMMON', '環境': 'ENVIRONMENT', 'ENVIRONMENT': 'ENVIRONMENT'}


class ChangeRecord(StrictModel):
    change_id: str = Field(pattern=r'^chg-[0-9a-f]{16}$')
    row_id: str
    scope: Literal['COMMON', 'ENVIRONMENT']
    resource_id: ID
    environment_id: ID
    property: str
    before: JsonValue = None
    after: JsonValue = None
    reason: str = Field(min_length=1)
    approved_by: str = Field(min_length=1)
    approved_at: str
    proposal_sha256: str
    workbook_sha256: str


def digest(raw):return hashlib.sha256(raw).hexdigest()


def exc_message():
    exc = sys.exc_info()[1]
    return str(exc) if type(exc) is ValueError or type(exc).__name__ == 'InputError' else ''


def read_workbook(path):
    """Return the import key and proposals per item; continuation rows are merged."""
    from openpyxl import load_workbook
    from .document_workbook import EDIT_COLUMNS, IMPORT_KEY
    book = load_workbook(path, read_only=True)
    try:
        key = ''.join(str(r[2] or '') for r in book['概要'].iter_rows(min_row=2, values_only=True) if r[0] == IMPORT_KEY) if '概要' in book.sheetnames else ''
        if not key:raise ValueError('workbook has no import key; regenerate it with this version')
        meta = json.loads(key)
        cells = {}
        for ws in book:
            if not ws.title.endswith('設定'):continue
            header = [c.value for c in next(ws.iter_rows(min_row=1, max_row=1))]
            if not all(name in header for name in EDIT_COLUMNS):continue
            index = {name: header.index(name) for name in EDIT_COLUMNS}
            for row_number, row in enumerate(ws.iter_rows(min_row=2), 2):
                item_id = row[0].value
                for name, col in index.items():
                    cell = row[col] if col < len(row) else None
                    if cell is None or cell.value is None or cell.value == '':continue
                    entry = cells.setdefault(item_id, {'sheet': ws.title, 'rows': [], **{n: [] for n in EDIT_COLUMNS}})
                    entry[name].append((cell.value, cell.data_type, row_number))
                    if row_number not in entry['rows']:entry['rows'].append(row_number)
        return meta, cells
    finally:
        book.close()


def parse_cell(value, data_type):
    """JSON when it parses, otherwise the literal text. Formulas and dates are refused."""
    if data_type == 'f' or isinstance(value, str) and value.startswith('='):raise ValueError('FORMULA')
    if isinstance(value, bool) or isinstance(value, (int, float)):return 'VALUE', value
    if not isinstance(value, str):raise ValueError('UNSUPPORTED_CELL_TYPE')
    text = value.strip()
    if text in UNDECIDED_WORDS:return 'UNDECIDED', None
    try:return 'VALUE', json.loads(text)
    except json.JSONDecodeError:return 'VALUE', text


def locate(data, environment, resource_id, scope):
    """The setting dict at a scope, creating no structure."""
    resource = next(r for r in data['resources'] if r['id'] == resource_id)
    if scope == 'COMMON':return resource.setdefault('settings', {})
    env = next(e for e in data['environments'] if e['id'] == environment)
    override = next((o for o in env.get('overrides', []) if o['resource_id'] == resource_id), None)
    if override is None:
        override = {'resource_id': resource_id, 'settings': {}};env.setdefault('overrides', []).append(override)
    return override['settings']


def propose(input_path, workbooks):
    from pydantic import ValidationError
    from .document_normalize import parse, secret_literal
    from .document_v11 import SchemaInput
    from .document_workbook import EDIT_COLUMNS
    raw = Path(input_path).read_bytes(); data = parse(raw); input_sha = digest(raw)
    if not isinstance(data, dict) or data.get('schema_version') != '1.1':raise ValueError('change proposals require a 1.1 input')
    changes, rejected, sources, environment = [], [], [], None
    value_col, reason_col, scope_col = EDIT_COLUMNS
    for path in workbooks:
        meta, cells = read_workbook(path)
        if meta.get('input_sha256') != input_sha:raise ValueError('STALE_WORKBOOK: workbook was generated from a different input')
        if environment not in (None, meta['environment_id']):raise ValueError('workbooks cover different environments')
        environment = meta['environment_id']; workbook_sha = digest(Path(path).read_bytes())
        sources.append({'file': Path(path).name, 'sha256': workbook_sha})
        for item_id, entry in sorted(cells.items(), key=lambda x: str(x[0])):
            where = {'workbook': Path(path).name, 'sheet': entry['sheet'], 'rows': entry['rows']}
            def reject(code):rejected.append({'item_id': item_id, 'environment_id': environment, 'code': code, **where})
            if any(len(entry[c]) > 1 for c in EDIT_COLUMNS):reject('AMBIGUOUS_CELLS');continue
            if not entry[value_col]:reject('VALUE_REQUIRED');continue
            reason = entry[reason_col][0][0] if entry[reason_col] else ''
            if not isinstance(reason, str) or not reason.strip():reject('REASON_REQUIRED');continue
            if not isinstance(item_id, str) or '.' not in item_id:reject('UNKNOWN_ITEM');continue
            resource_id, prop = item_id.split('.', 1)
            resource = next((r for r in data['resources'] if r['id'] == resource_id), None)
            if resource is None:reject('UNKNOWN_ITEM');continue
            try:kind, value = parse_cell(*entry[value_col][0][:2])
            except ValueError as exc:reject(str(exc));continue
            if kind == 'VALUE' and secret_literal(value):reject('SECRET_LIKE');continue
            env = next(e for e in data['environments'] if e['id'] == environment)
            override = next((o for o in env.get('overrides', []) if o['resource_id'] == resource_id), {})
            origin = 'ENVIRONMENT' if prop in override.get('settings', {}) else 'COMMON'
            requested = str(entry[scope_col][0][0]).strip() if entry[scope_col] else ''
            scope = (SCOPES.get(requested) or SCOPES.get(requested.upper())) if requested else origin
            if scope is None:reject('UNKNOWN_SCOPE');continue
            before = (override.get('settings', {}) if scope == 'ENVIRONMENT' else resource.get('settings', {})).get(prop)
            current = override.get('settings', {}).get(prop) or resource.get('settings', {}).get(prop)
            if current and (current.get('mode') in ('COMPOSITE', 'SECRET_REF') or current.get('classification') == 'SECRET'):
                reject('UNSUPPORTED_TARGET_MODE');continue
            kept = {k: v for k, v in (before or current or {}).items() if k in ('classification', 'rationale', 'sources', 'decision_ids')}
            after = {'status': 'UNDECIDED', **{k: v for k, v in kept.items() if k != 'classification'}} if kind == 'UNDECIDED' else {'mode': 'LITERAL', 'value': value, **kept}
            if before == after:reject('UNCHANGED');continue
            trial = copy.deepcopy(data);locate(trial, environment, resource_id, scope)[prop] = after
            try:SchemaInput.model_validate(trial)
            except ValidationError:reject('INVALID_FOR_SCHEMA');continue
            identity = json.dumps([input_sha, environment, item_id, scope, after], sort_keys=True, ensure_ascii=False)
            changes.append({'change_id': 'chg-' + digest(identity.encode())[:16], 'row_id': environment + '/' + item_id,
                            'item_id': item_id, 'resource_id': resource_id, 'property': prop, 'environment_id': environment,
                            'scope': scope, 'before': before, 'after': after, 'reason': reason.strip(),
                            'workbook_sha256': workbook_sha, **where})
    targets = [(c['scope'], c['resource_id'], c['property'], c['environment_id'] if c['scope'] == 'ENVIRONMENT' else '') for c in changes]
    if len(targets) != len(set(targets)):raise ValueError('several proposals target one setting; resolve them in the workbook')
    return {'format_version': '1.0', 'status': 'PROPOSED', 'input_sha256': input_sha, 'environment_id': environment,
            'workbooks': sources, 'changes': changes, 'rejected': rejected,
            'summary': {'changes': len(changes), 'rejected': len(rejected),
                        'rejected_codes': {c: sum(r['code'] == c for r in rejected) for c in sorted({r['code'] for r in rejected})}},
            'notes': ['入力ファイルは変更していません。apply で承認者を指定して反映してください。',
                      '修正案の値はJSONとして解釈できればJSON、できなければ文字列として扱います。「未決定」は UNDECIDED です。']}


def apply(input_path, proposal_path, output_path, approver, change_ids=None):
    from .document_normalize import parse
    from .document_v11 import SchemaInput
    if not approver or not approver.strip():raise ValueError('approver is required')
    output_path = Path(output_path)
    if output_path.resolve() == Path(input_path).resolve():raise ValueError('output must differ from the input')
    if output_path.exists():raise ValueError('output already exists; use a fresh path')
    raw = Path(input_path).read_bytes(); proposal_raw = Path(proposal_path).read_bytes()
    proposal = json.loads(proposal_raw); data = parse(raw)
    if proposal.get('status') != 'PROPOSED' or proposal.get('input_sha256') != digest(raw):
        raise ValueError('STALE_PROPOSAL: the input changed after the proposal was made')
    known = {c['change_id']: c for c in proposal['changes']}
    selected = list(known) if change_ids is None else change_ids
    if not selected or set(selected) - set(known) or len(selected) != len(set(selected)):raise ValueError('unknown or duplicate change ID')
    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    log = data.setdefault('change_log', [])
    for change_id in selected:
        c = known[change_id]
        settings = locate(data, c['environment_id'], c['resource_id'], c['scope'])
        if settings.get(c['property']) != c['before']:raise ValueError('STALE_PROPOSAL: target setting changed')
        settings[c['property']] = c['after']
        log.append(ChangeRecord(change_id=c['change_id'], row_id=c['row_id'], scope=c['scope'], resource_id=c['resource_id'],
            environment_id=c['environment_id'], property=c['property'], before=c['before'], after=c['after'], reason=c['reason'],
            approved_by=approver.strip(), approved_at=now, proposal_sha256=digest(proposal_raw),
            workbook_sha256=c['workbook_sha256']).model_dump(mode='json'))
    SchemaInput.model_validate(data)
    encoded = (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open('xb') as stream:stream.write(encoded)
    return {'status': 'APPLIED', 'applied': selected, 'not_applied': sorted(set(known) - set(selected)),
            'environment_id': proposal['environment_id'], 'output': str(output_path), 'output_sha256': digest(encoded),
            'output_format': 'JSON'}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    a = sub.add_parser('propose', help='read edit columns and write a change proposal')
    a.add_argument('input', type=Path);a.add_argument('workbooks', type=Path, nargs='+', help='generated 1.1 workbooks or an output directory')
    a.add_argument('--output', type=Path, required=True)
    b = sub.add_parser('apply', help='apply approved proposals to a new input file')
    b.add_argument('input', type=Path);b.add_argument('proposal', type=Path)
    b.add_argument('--output', type=Path, required=True);b.add_argument('--approver', required=True)
    b.add_argument('--change', action='append', dest='changes', help='change ID to approve; repeatable')
    b.add_argument('--all', action='store_true', help='approve every proposed change')
    b.add_argument('--generate', type=Path, help='regenerate the document for the proposal environment into this fresh directory')
    args = p.parse_args(argv)
    try:
        if args.command == 'propose':
            if args.output.exists():raise ValueError('output already exists; use a fresh path')
            books = [x for w in args.workbooks for x in (sorted(w.glob('*.xlsx')) if w.is_dir() else [w])]
            result = propose(args.input, books)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            print(json.dumps({'status': result['status'], **result['summary']}, ensure_ascii=False));return 0
        if args.all == bool(args.changes):raise ValueError('choose --all or one or more --change')
        result = apply(args.input, args.proposal, args.output, args.approver, None if args.all else args.changes)
        if args.generate:
            from .document_cli import generate
            summary = generate(args.output, result['environment_id'], args.generate)
            result['generated'] = {k: summary.get(k) for k in ('generation_status', 'input_completeness', 'project_policy_assessment',
                                                               'design_decision_assessment')}
        print(json.dumps(result, ensure_ascii=False));return 0
    except ValidationError:
        # Validation errors can echo input values; report only that validation failed.
        print(json.dumps({'status': 'FAILED', 'message': 'Changed input failed validation; no file was written.'}));return 2
    except (ValueError, OSError, KeyError, StopIteration):
        # ValueError messages raised here and by the parser are fixed texts without values.
        message = str(exc_message()) or 'Change processing failed; no input was modified.'
        print(json.dumps({'status': 'FAILED', 'message': message}, ensure_ascii=False));return 2


if __name__ == '__main__':raise SystemExit(main())
