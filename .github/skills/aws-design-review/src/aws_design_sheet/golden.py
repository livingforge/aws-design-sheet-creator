"""Golden set: agent outputs on cases whose right answer people settled, scored against thresholds.

A manifest lists cases: an external-sheet items file, a system overview or agent verdicts on a
review packet, each with the expected file and the inputs needed to compare. `score` reads the
candidate outputs (one `<case id>.json` per case in a folder), compares them with the same
structural readings the cross-checks use (cells claimed, requirement placements, verdicts by
row key), and reports per case and per delegation rule. Run it whenever an agent's prompt or
model changes; `aws-design delegation calibrate --golden REPORT` suspends a rule whose cases fail.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

RULE_OF = {'external-items': 'external_mapping', 'system-overview': 'overview', 'agent-verdicts': 'review'}


class InputError(ValueError):
    pass


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Case(Strict):
    id: str = Field(pattern=r'^[a-z][a-z0-9-]{0,63}$')
    kind: Literal['external-items', 'system-overview', 'agent-verdicts']
    expected: str
    extraction: str | None = None
    structure: str | None = None
    document: str | None = None
    dictionary: str | None = None
    packet: str | None = None
    key: str | None = None
    min_agreement: float = Field(default=0.95, ge=0, le=1)


class GoldenManifest(Strict):
    contract: Literal['golden-manifest/1']
    id: str = Field(pattern=r'^[a-z][a-z0-9-]{0,63}$')
    description: str = ''
    cases: list[Case] = Field(min_length=1)


class CaseResult(Strict):
    id: str
    kind: str
    status: Literal['PASS', 'FAIL', 'MISSING', 'INVALID']
    agreement: float | None = None
    detail: str = ''
    differences: list[dict] = Field(default_factory=list, max_length=50)


class GoldenReport(Strict):
    contract: Literal['golden-report/1']
    manifest_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    candidate: str
    status: Literal['PASS', 'FAIL']
    cases: list[CaseResult]
    rules: dict[str, Literal['PASS', 'FAIL']] = Field(default_factory=dict)


def external_items(case, base, candidate_raw):
    from .external_sheet import ItemsFile, Sheetbook, load_dictionary, reading
    book = Sheetbook((base / case.extraction).read_bytes(), (base / case.structure).read_bytes(),
                     (base / case.document).read_bytes() if case.document else None)
    dictionary, _ = load_dictionary((base / case.dictionary).read_bytes() if case.dictionary else None)
    expected = reading(book, ItemsFile.model_validate_json((base / case.expected).read_bytes()), dictionary)
    got = reading(book, ItemsFile.model_validate_json(candidate_raw), dictionary)
    cells = sorted(set(expected) | set(got))
    wrong = [c for c in cells if expected.get(c) != got.get(c)]
    differences = [{'cell': c, 'fields': ['cited'] if c not in expected or c not in got else
                    sorted(k for k in set(expected[c]) | set(got[c]) if expected[c].get(k) != got[c].get(k))} for c in wrong]
    return (1 - len(wrong) / len(cells)) if cells else 1.0, f'{len(cells)} cells, {len(wrong)} differ', differences, True


def system_overview(case, base, candidate_raw):
    from .system_overview import compare, load
    expected = load((base / case.expected).read_bytes()).model_copy(update={'author': None})
    got = load(candidate_raw)
    found = compare(expected, got)
    differences = [{'requirement': d['requirement']} for d in found['requirement_differences']]
    differences += [{'quality_target': d['attribute']} for d in found['quality_target_differences']]
    # A wrong quality target is a wrong number in the overview; it fails the case whatever the placement rate.
    return found['agreement_rate'], f"requirements {found['requirements_compared']}, targets differing {len(found['quality_target_differences'])}", differences, \
        not found['quality_target_differences']


def agent_verdicts(case, base, candidate_raw):
    from .review_agents import AgentVerdicts, CanaryKey
    expected = {v.key: v.verdict for v in AgentVerdicts.model_validate_json((base / case.expected).read_bytes()).verdicts}
    got = {v.key: v.verdict for v in AgentVerdicts.model_validate_json(candidate_raw).verdicts}
    canaries = set()
    if case.key:canaries = {k for k, v in CanaryKey.model_validate_json((base / case.key).read_bytes()).rows.items() if v.canary}
    wrong = [k for k in expected if got.get(k) != expected[k]]
    missed = [k for k in canaries if got.get(k) != 'NG']
    differences = [{'key': k, 'expected': expected[k], 'got': got.get(k)} for k in wrong]
    return (1 - len(wrong) / len(expected)) if expected else 1.0, f'{len(expected)} rows, {len(wrong)} differ, canaries missed {len(missed)}', differences, not missed


SCORERS = {'external-items': external_items, 'system-overview': system_overview, 'agent-verdicts': agent_verdicts}


def score(manifest_path, candidates, candidate_label):
    manifest_path = Path(manifest_path);raw = manifest_path.read_bytes()
    manifest = GoldenManifest.model_validate_json(raw)
    base = manifest_path.parent
    results = []
    for case in manifest.cases:
        path = Path(candidates) / f'{case.id}.json'
        if not path.is_file():
            results.append(CaseResult(id=case.id, kind=case.kind, status='MISSING', detail=str(path.name)));continue
        try:agreement, detail, differences, extra_ok = SCORERS[case.kind](case, base, path.read_bytes())
        except (ValidationError, ValueError) as exc:
            results.append(CaseResult(id=case.id, kind=case.kind, status='INVALID', detail=str(exc).split(':', 1)[0][:120]));continue
        status = 'PASS' if agreement >= case.min_agreement and extra_ok else 'FAIL'
        results.append(CaseResult(id=case.id, kind=case.kind, status=status, agreement=round(agreement, 4), detail=detail, differences=differences[:50]))
    rules = {}
    for r in results:
        rule = RULE_OF[r.kind]
        rules[rule] = 'FAIL' if r.status != 'PASS' or rules.get(rule) == 'FAIL' else 'PASS'
    return GoldenReport(contract='golden-report/1', manifest_sha256=hashlib.sha256(raw).hexdigest(), candidate=candidate_label,
                        status='PASS' if all(r.status == 'PASS' for r in results) else 'FAIL', cases=results, rules=rules)


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design golden', description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('score', help='score candidate outputs against a golden manifest')
    p.add_argument('--manifest', required=True);p.add_argument('--candidates', required=True, help='folder with <case id>.json files')
    p.add_argument('--candidate', required=True, help='label of the agent and model that produced the candidates');p.add_argument('--output')
    args = parser.parse_args(argv)
    try:
        report = score(args.manifest, args.candidates, args.candidate)
        text = json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + '\n'
        if args.output:
            out = Path(args.output)
            if out.exists():raise InputError('output already exists; use a fresh path')
            out.parent.mkdir(parents=True, exist_ok=True);out.write_text(text, encoding='utf-8')
        sys.stdout.buffer.write(text.encode('utf-8'));return 0 if report.status == 'PASS' else 3
    except ValidationError as exc:
        errors = [{'loc': [str(x) for x in e['loc']], 'type': e['type']} for e in exc.errors(include_input=False, include_context=False)]
        print(json.dumps({'status': 'ERROR', 'message': 'CONTRACT_INVALID', 'errors': errors}, ensure_ascii=False));return 2
    except (InputError, OSError, ValueError) as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc) if isinstance(exc, InputError) else type(exc).__name__}, ensure_ascii=False));return 2


if __name__ == '__main__':
    raise SystemExit(main())
