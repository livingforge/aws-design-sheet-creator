"""Contracts: every file agents and people hand over has a JSON Schema and one validator.

`validate` recognises a file's contract from its own fields (an explicit `contract` value,
else the version and the keys each legacy format has always carried), validates it with the
same model the commands use, including cross-reference checks, and reports error locations
and types only, never values. `export` writes the JSON Schemas to schemas/contracts so other
tools can validate without this package; a test keeps them equal to the models. The design
input's schema depends on the regional CloudFormation catalog and is printed by
`aws-design document --schema input --schema-version 1.1` instead.
"""
import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

EXPORT_DIR = Path(__file__).resolve().parents[2] / 'schemas' / 'contracts'
# Workspace folders whose JSON files are handover contracts; tool reports in runs/NNN are outputs, not handovers.
WORKSPACE_GLOBS = ('flow.json', 'sources/*.json', 'input/*.json', 'input/*.yaml', 'input/*.yml', 'reviews/*.json', 'delegation/*.json',
                   'delegation/log/*.json', 'delegation/audits/*.json', 'runs/*/gates.json', 'runs/*/agent-review/*.json',
                   'asks/ledger.json', 'asks/review-*.json', 'asks/records/*.json', 'asks/batches/*/manifest.json')


class InputError(ValueError):
    pass


def source_trace_model():
    """The shape of an external-sheet source trace; its bindings to generated items are checked at generation."""
    from typing import Literal
    from pydantic import BaseModel, ConfigDict, Field

    class Row(BaseModel):
        model_config = ConfigDict(extra='allow')
        setting_id: str = Field(min_length=1)
        kind: Literal['CFN', 'APP']
        source_snapshot: dict
        item_ids: list[str] = Field(default_factory=list)

    class SourceTrace(BaseModel):
        model_config = ConfigDict(extra='allow')
        rows: list[Row] = Field(max_length=10000)
    return SourceTrace


def models():
    """Contract name → Pydantic model, for every contract with a static schema."""
    from .asks import AskReview, Batch, Ledger, Records
    from .delegation import AutoDecision, Calibration, Policy, PolicyApproval
    from .external_sheet import Dictionary, ItemsFile, Review
    from .flow import FlowConfig
    from .gates import GateReport
    from .golden import GoldenManifest, GoldenReport
    from .calibration import AuditRecord
    from .review_agents import AgentVerdicts, Escalation, Packet
    from .review_pack import Decisions
    from .source_set import SourceSet
    from .system_overview import Overview, OverviewApproval, OverviewReview
    return {'flow-config': FlowConfig, 'source-set': SourceSet, 'system-overview': Overview, 'overview-review': OverviewReview,
            'overview-approval': OverviewApproval, 'external-items': ItemsFile, 'external-dictionary': Dictionary, 'external-review': Review,
            'review-decisions': Decisions, 'review-packet': Packet, 'agent-verdicts': AgentVerdicts, 'agent-escalation': Escalation,
            'delegation-policy': Policy, 'delegation-approval': PolicyApproval, 'delegation-calibration': Calibration,
            'auto-decision': AutoDecision, 'audit-record': AuditRecord, 'gate-report': GateReport,
            'golden-manifest': GoldenManifest, 'golden-report': GoldenReport, 'source-trace': source_trace_model(),
            'ask-ledger': Ledger, 'ask-review': AskReview, 'ask-records': Records, 'ask-batch': Batch}


KINDS = ('design-input', *('flow-config', 'source-set', 'system-overview', 'overview-review', 'overview-approval', 'external-items',
                          'external-dictionary', 'external-review', 'review-decisions', 'review-packet', 'agent-verdicts', 'agent-escalation',
                          'delegation-policy', 'delegation-approval', 'delegation-calibration', 'auto-decision', 'audit-record', 'gate-report',
                          'golden-manifest', 'golden-report', 'source-trace', 'ask-ledger', 'ask-review', 'ask-records', 'ask-batch'))


def detect(data):
    """The contract a parsed file claims, or None."""
    if not isinstance(data, dict):return None
    declared = data.get('contract')
    if isinstance(declared, str) and '/' in declared:
        kind = declared.split('/', 1)[0]
        return kind if kind in KINDS else None
    version, schema = data.get('version'), data.get('schema_version')
    if schema in ('1.0', '1.1'):return 'design-input'
    if schema == '1':
        if data.get('kind') in ('proposal', 'approved'):return 'source-set'
        if 'binding' in data:return 'external-items'
        if 'items_sha256' in data:return 'external-review'
        if 'system' in data:return 'system-overview'
        if 'entries' in data or 'state_words' in data:return 'external-dictionary'
    if version == '1':
        if 'overview_sha256' in data:return 'overview-review' if 'decision' in data else 'overview-approval'
        if 'decisions' in data and set(data) <= {'version', 'decisions'}:return 'review-decisions'
    if 'environment' in data and 'input' in data and 'schema_version' not in data:return 'flow-config'
    if 'rows' in data and version is None and schema is None:return 'source-trace'
    return None


def errors_of(exc):return [{'loc': [str(x) for x in e['loc']], 'type': e['type']} for e in exc.errors(include_input=False, include_context=False)]


def check(raw, kind=None):
    """(kind, errors): errors is empty when the bytes satisfy the contract."""
    from .document_normalize import InputError as ParseError, parse
    try:data = parse(raw)
    except ParseError:return kind, [{'loc': [], 'type': 'NOT_JSON_OR_YAML'}]
    found = detect(data)
    if kind is None:kind = found
    if kind is None:return None, [{'loc': [], 'type': 'UNKNOWN_CONTRACT'}]
    if kind not in KINDS:raise InputError(f'UNKNOWN_KIND: {kind}')
    try:
        if kind == 'design-input':
            from .document_model import DocumentInput
            from .document_v11 import SchemaInput
            (SchemaInput if isinstance(data, dict) and data.get('schema_version') == '1.1' else DocumentInput).model_validate(data)
        elif kind == 'system-overview':
            from .system_overview import load
            load(raw)
        else:
            models()[kind].model_validate(data)
            if kind == 'source-set' and data.get('kind') == 'approved':
                from .source_set import load_approved
                load_approved(raw)
    except ValidationError as exc:return kind, errors_of(exc)
    except ValueError as exc:
        # Cross-reference errors carry a code before the colon; anything after it may name IDs, never values.
        return kind, [{'loc': [], 'type': str(exc).split(':', 1)[0][:80] or type(exc).__name__}]
    return kind, []


def validate(path, kind=None):
    path = Path(path)
    try:raw = path.read_bytes()
    except OSError as exc:return {'file': str(path), 'kind': kind, 'status': 'FAIL', 'errors': [{'loc': [], 'type': type(exc).__name__}]}
    found, errors = check(raw, kind)
    return {'file': str(path), 'kind': found, 'status': 'FAIL' if errors else 'PASS', 'errors': errors}


def workspace_files(workspace):
    workspace = Path(workspace)
    seen = []
    for pattern in WORKSPACE_GLOBS:
        for path in sorted(workspace.glob(pattern)):
            if path.is_file() and path not in seen and not path.name.endswith('.previous'):seen.append(path)
    return seen


def validate_workspace(workspace):
    """Every handover file of a workspace; unknown files in those folders fail, so nothing slips past unchecked."""
    rows = [validate(p) for p in workspace_files(workspace)]
    for r in rows:r['file'] = Path(r['file']).relative_to(workspace).as_posix()
    failed = [r for r in rows if r['status'] == 'FAIL']
    return {'status': 'FAIL' if failed else 'PASS', 'files': len(rows), 'failed': len(failed), 'results': rows}


def schemas():
    return {kind: model.model_json_schema() for kind, model in models().items()}


def export(folder=EXPORT_DIR):
    folder = Path(folder);folder.mkdir(parents=True, exist_ok=True)
    written = []
    for kind, schema in schemas().items():
        schema = {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': f'aws-design-sheet/{kind}', **schema}
        (folder / f'{kind}.schema.json').write_bytes((json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode('utf-8'))
        written.append(kind)
    return written


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design contract', description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('list', help='contract names')
    p = sub.add_parser('schema', help='print the JSON Schema of one contract');p.add_argument('--kind', required=True, choices=[k for k in KINDS if k != 'design-input'])
    p = sub.add_parser('validate', help='validate files, or every handover file of a workspace')
    p.add_argument('files', nargs='*');p.add_argument('--kind', choices=KINDS);p.add_argument('--workspace')
    p = sub.add_parser('export', help='write every JSON Schema to a folder');p.add_argument('--output', default=str(EXPORT_DIR))
    args = parser.parse_args(argv)
    try:
        if args.command == 'list':
            print(json.dumps(list(KINDS)));return 0
        if args.command == 'schema':
            print(json.dumps(schemas()[args.kind], ensure_ascii=False, indent=2));return 0
        if args.command == 'export':
            print(json.dumps({'written': export(args.output), 'folder': args.output}, ensure_ascii=False));return 0
        if not args.files and not args.workspace:raise InputError('give files or --workspace')
        results = [validate(f, args.kind) for f in args.files]
        report = {'status': 'FAIL' if any(r['status'] == 'FAIL' for r in results) else 'PASS', 'results': results}
        if args.workspace:
            ws = validate_workspace(Path(args.workspace))
            report = {'status': 'FAIL' if 'FAIL' in (report['status'] if results else 'PASS', ws['status']) else 'PASS',
                      'results': results + ws['results']}
        sys.stdout.buffer.write((json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
        return 0 if report['status'] == 'PASS' else 2
    except (InputError, OSError) as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc) if isinstance(exc, InputError) else type(exc).__name__}, ensure_ascii=False));return 2


if __name__ == '__main__':
    raise SystemExit(main())
