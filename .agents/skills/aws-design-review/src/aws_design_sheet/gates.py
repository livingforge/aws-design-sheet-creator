"""Quality gates: machine checks a workspace must pass before agents may decide anything on it.

Each generation writes runs/NNN/gates.json. The gates are: every handover file satisfies its
contract; the approved source set still matches ARP4 and the design cites only citable
documents; every value the design takes from a document is found where it cites it, and a
planted value is not (the grounding self-test); the system overview has no conflict; the
generation itself completed; every drawing of the CURRENT documents has a reviewed disposition and the design
input maps what the diagrams draw (the diagram coverage); every AWS service the CURRENT documents name in their
cells and drawings is in the input, or a note or decision of the input cites where it is named (the service
mentions). FAIL stops the workflow until the input is fixed; WARN lets it
continue and the warnings stay on the review pack. A gate result is about the agents'
handover, never about whether the AWS design is good.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

GATES = ('contracts', 'source_set', 'grounding', 'grounding_self_test', 'diagram_coverage', 'service_mentions', 'overview', 'generation')
GATES_JA = {'contracts': '契約（スキーマ）', 'source_set': '根拠文書セット', 'grounding': '引用の裏付け', 'grounding_self_test': '裏付け検査の自己試験',
            'diagram_coverage': '構成図の対比カバレッジ', 'service_mentions': '文書が名指すサービス', 'overview': 'システム概要の矛盾', 'generation': '生成の完了'}
State = Literal['PASS', 'WARN', 'FAIL', 'SKIPPED']


class InputError(ValueError):
    pass


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Gate(Strict):
    id: Literal[GATES]
    status: State
    detail: str = ''
    counts: dict[str, int] = Field(default_factory=dict)
    # Pointers, file names and codes only, at most 50.
    items: list[dict] = Field(default_factory=list, max_length=50)


class GateReport(Strict):
    contract: Literal['gate-report/1']
    run: str | None = None
    status: Literal['PASS', 'WARN', 'FAIL']
    gates: list[Gate]
    inputs: dict[str, str | None] = Field(default_factory=dict)


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest() if path and Path(path).is_file() else None


def overall(gates):
    states = {g.status for g in gates}
    return 'FAIL' if 'FAIL' in states else 'WARN' if 'WARN' in states else 'PASS'


def evaluate(workspace, run=None, *, keep=None):
    """Gate report for the workspace as it stands, attributed to a run folder when given. `keep` receives the
    diagram coverage report, which the run folder holds beside the gates."""
    from . import flow
    from .contracts import validate_workspace
    from .document_normalize import InputError as ParseError, parse
    workspace = Path(workspace);config = flow.load(workspace)
    gates = []
    contracts = validate_workspace(workspace)
    failed = [r for r in contracts['results'] if r['status'] == 'FAIL']
    gates.append(Gate(id='contracts', status='FAIL' if failed else 'PASS', detail=f"{contracts['files']} files, {len(failed)} failed",
                      items=[{'file': r['file'], 'kind': r['kind'], 'errors': [e['type'] for e in r['errors']][:5]} for r in failed][:50]))
    design_path = flow.generation_input(workspace, config)
    design = None
    if design_path and design_path.is_file():
        try:design = parse(design_path.read_bytes())
        except ParseError:design = None
    set_path = workspace / 'sources' / 'set.json'
    library = None
    if config.get('arp_root') and set_path.is_file():
        from .source_set import InputError as SetError, check
        try:
            report = check(Path(config['arp_root']), set_path.read_bytes(), design if isinstance(design, dict) else None)
            gates.append(Gate(id='source_set', status='FAIL' if report['errors'] else 'WARN' if report['warnings'] else 'PASS',
                              detail=f"errors {len(report['errors'])}, warnings {len(report['warnings'])}",
                              items=[{k: v for k, v in e.items() if k in ('code', 'document', 'source', 'pointer', 'family')} for e in report['errors'] + report['warnings']][:50]))
            from .grounding import Library
            library = Library.from_arp(Path(config['arp_root']), set_path.read_bytes())
        except (SetError, ValueError) as exc:
            gates.append(Gate(id='source_set', status='FAIL', detail=str(exc).split(':', 1)[0][:120]))
    else:gates.append(Gate(id='source_set', status='SKIPPED', detail='no approved source set'))
    if isinstance(design, dict):
        from .grounding import ground, self_test
        trace_rows = None
        if config.get('source_trace') and flow.at(workspace, config['source_trace']).is_file():
            trace_rows = json.loads(flow.at(workspace, config['source_trace']).read_text(encoding='utf-8')).get('rows', [])
        grounded = ground(design, library, trace_rows)
        weak_or_failing = [r for r in grounded['rows'] if r['status'] not in ('GROUNDED', 'TRACED', 'DECISION', 'INTERPRETED')]
        gates.append(Gate(id='grounding', status=grounded['status'], counts=grounded['counts'],
                          detail='、'.join(f'{k} {v}' for k, v in grounded['counts'].items()) or 'no document values claimed',
                          items=[{k: r.get(k) for k in ('pointer', 'status', 'detail', 'source')} for r in weak_or_failing][:50]))
        tested = self_test(design, library, trace_rows)
        gates.append(Gate(id='grounding_self_test', status=tested['status'], detail=tested['detail']))
    else:
        gates.append(Gate(id='grounding', status='FAIL', detail='design input missing or unreadable'))
        gates.append(Gate(id='grounding_self_test', status='SKIPPED', detail='no design input'))
    gates.append(diagram_gate(workspace, config, design, keep))
    gates.append(mentions_gate(design, library, keep))
    overview_path = flow.at(workspace, config.get('overview'))
    if overview_path and overview_path.is_file():
        from .system_overview import check as check_overview, load as load_overview
        try:
            found = check_overview(load_overview(overview_path.read_bytes()), design if isinstance(design, dict) else None)
            conflicts = [f for f in found['findings'] if f['category'] == 'CONFLICT']
            gates.append(Gate(id='overview', status='FAIL' if conflicts else 'PASS', detail=found['assessment'],
                              items=[{'code': f['code'], 'target': f['target']} for f in conflicts][:50]))
        except ValueError as exc:
            gates.append(Gate(id='overview', status='FAIL', detail=str(exc).split(':', 1)[0][:120]))
    else:gates.append(Gate(id='overview', status='SKIPPED', detail='no system overview'))
    run_folder = workspace / 'runs' / run if run else None
    if run_folder and (run_folder / 'flow-run.json').is_file():
        meta = json.loads((run_folder / 'flow-run.json').read_text(encoding='utf-8'))
        gates.append(Gate(id='generation', status='FAIL' if meta.get('exit_code') == 2 else 'PASS', detail=f"exit {meta.get('exit_code')}"))
    else:gates.append(Gate(id='generation', status='SKIPPED', detail='no run'))
    return GateReport(contract='gate-report/1', run=run, status=overall(gates), gates=gates,
                      inputs={'design_input': sha(design_path), 'source_set': sha(set_path), 'system_overview': sha(overview_path)})


def diagram_gate(workspace, config, design, keep=None):
    """Every drawing of the CURRENT documents has a reviewed disposition, and the input maps what the diagrams draw."""
    set_path = Path(workspace) / 'sources' / 'set.json'
    if not config.get('arp_root') or not set_path.is_file():return Gate(id='diagram_coverage', status='SKIPPED', detail='no approved source set')
    from .diagram_ledger import InputError as LedgerError, workspace_report
    try:report = workspace_report(workspace, Path(config['arp_root']), set_path.read_bytes(), design if isinstance(design, dict) else {})
    except (LedgerError, ValueError) as exc:return Gate(id='diagram_coverage', status='FAIL', detail=str(exc).split(':', 1)[0][:120])
    if report is None:return Gate(id='diagram_coverage', status='SKIPPED', detail='no drawings in the CURRENT documents')
    if keep is not None:keep['diagram_coverage'] = report
    counts = {k: v for k, v in report['counts'].items() if v}
    ordered = [f for f in report['findings'] if f['severity'] == 'FAIL'] + [f for f in report['findings'] if f['severity'] == 'WARN']
    return Gate(id='diagram_coverage', status=report['status'], counts=counts,
                detail=f"coverage {report['coverage_percent']}%, findings {len(report['findings'])}",
                items=[{k: f.get(k) for k in ('code', 'severity', 'document', 'ref', 'target')} for f in ordered][:50])


def mentions_gate(design, library, keep=None):
    """Every AWS service the CURRENT documents name is in the input, or the input notes why not."""
    if library is None:return Gate(id='service_mentions', status='SKIPPED', detail='no approved source set')
    if not isinstance(design, dict):return Gate(id='service_mentions', status='SKIPPED', detail='no design input')
    from .service_mentions import report
    found = report(design, library)
    if keep is not None:keep['service_mentions'] = found
    c = found['counts']
    missing = [s for s in found['services'] if s['status'] == 'NOT_IN_DESIGN']
    return Gate(id='service_mentions', status=found['status'], counts={k: v for k, v in c.items() if v},
                detail=f"services {c['services_named']}, in design {c['IN_DESIGN']}, noted {c['NOTED']}, not in design {c['NOT_IN_DESIGN']}",
                items=[{'code': 'SERVICE_NOT_IN_DESIGN', 'service': s['label'], 'mentions': s['mentions'], 'refs': s['refs'][:3]} for s in missing][:50])


def write(workspace, run):
    kept = {}
    report = evaluate(workspace, run, keep=kept)
    folder = Path(workspace) / 'runs' / run
    (folder / 'gates.json').write_text(json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if 'diagram_coverage' in kept:
        from .diagram_ledger import render as render_coverage
        (folder / 'diagram-coverage.json').write_text(json.dumps(kept['diagram_coverage'], ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (folder / 'diagram-coverage.md').write_text(render_coverage(kept['diagram_coverage']), encoding='utf-8')
    if 'service_mentions' in kept:
        from .service_mentions import render as render_mentions
        (folder / 'service-mentions.json').write_text(json.dumps(kept['service_mentions'], ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (folder / 'service-mentions.md').write_text(render_mentions(kept['service_mentions']), encoding='utf-8')
    return report


def load(path):return GateReport.model_validate_json(Path(path).read_bytes())


def render(report):
    lines = [f"# ゲート{' ' + report.run if report.run else ''}（{report.status}）", '', '| ゲート | 結果 | 内容 |', '|---|---|---|']
    lines += [f'| {GATES_JA[g.id]} | {g.status} | {g.detail} |' for g in report.gates]
    for g in report.gates:
        if g.status in ('FAIL', 'WARN') and g.items:
            lines += ['', f'## {GATES_JA[g.id]}（{g.status}）', '']
            lines += ['- ' + '、'.join(f'{k}={v}' for k, v in item.items() if v not in (None, '', [])) for item in g.items]
    lines += ['', 'ゲートはエージェントの受け渡し物の機械検査であり、設計の承認ではない。']
    return '\n'.join(lines) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design gate', description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('run', help='evaluate the gates of a workspace; with --run, write runs/NNN/gates.json')
    p.add_argument('--workspace', required=True);p.add_argument('--run');p.add_argument('--markdown', action='store_true')
    p = sub.add_parser('ground', help='grounding of one design input against an approved source set')
    p.add_argument('design');p.add_argument('--arp-root');p.add_argument('--source-set');p.add_argument('--source-trace')
    args = parser.parse_args(argv)
    try:
        if args.command == 'ground':
            from .document_normalize import parse
            from .grounding import Library, ground, self_test
            design = parse(Path(args.design).read_bytes())
            if not isinstance(design, dict):raise InputError('design input must be a mapping')
            if bool(args.arp_root) != bool(args.source_set):raise InputError('--arp-root and --source-set go together')
            library = Library.from_arp(Path(args.arp_root), Path(args.source_set).read_bytes()) if args.arp_root else None
            rows = json.loads(Path(args.source_trace).read_text(encoding='utf-8')).get('rows', []) if args.source_trace else None
            report = ground(design, library, rows);report['self_test'] = self_test(design, library, rows)
            print(json.dumps(report, ensure_ascii=False, indent=2));return 0 if report['status'] != 'FAIL' else 2
        if args.run:report = write(args.workspace, args.run)
        else:
            # Without --run, evaluate against the latest run and write nothing.
            from .flow import runs
            found = runs(Path(args.workspace))
            report = evaluate(args.workspace, found[-1].name if found else None)
        text = render(report) if args.markdown else json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + '\n'
        sys.stdout.buffer.write(text.encode('utf-8'));return 0 if report.status != 'FAIL' else 2
    except (InputError, OSError, ValueError) as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc).split(':', 1)[0][:200] if isinstance(exc, ValueError) else type(exc).__name__}, ensure_ascii=False));return 2


if __name__ == '__main__':
    raise SystemExit(main())
