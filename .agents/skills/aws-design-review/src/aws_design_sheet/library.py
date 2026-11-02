"""Organisation library: what one project learned, reused by the next.

A library folder holds an organisation-wide external-sheet dictionary (dictionary.json, with
promotions.json recording who promoted which entry from which project), policy packs
(policy-packs/*.json) and system-overview templates (overview-templates/*.json). `promote`
adds a project's approved dictionary entries, merging labels of entries that mean the same
mapping; only a person the user names promotes. `dictionary` merges the library with a
project dictionary for aws-design external. Policy packs and templates are found by name in
the library before the bundled ones.
"""
import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

BUNDLED = Path(__file__).resolve().parents[2] / 'profiles'


class InputError(ValueError):
    pass


def find(kind, name, library=None):
    """A policy pack or overview template by name or path: the library first, then the bundled profiles."""
    if name.endswith('.json'):
        path = Path(name)
        if not path.is_file():raise InputError(f'UNKNOWN_{kind.upper()}: {name}')
        return path
    for base in ([Path(library) / kind] if library else []) + [BUNDLED / kind]:
        if (base / f'{name}.json').is_file():return base / f'{name}.json'
    raise InputError(f'UNKNOWN_{kind.upper()}: {name}; available: ' + ', '.join(available(kind, library)))


def available(kind, library=None):
    names = set()
    for base in ([Path(library) / kind] if library else []) + [BUNDLED / kind]:
        if base.is_dir():names |= {p.stem for p in base.glob('*.json')}
    return sorted(names)


def merge(base, extra):
    """Two dictionaries as one: entries meaning the same mapping keep one ID and the union of labels; words are united."""
    from .external_sheet import Dictionary, canonical, label_norm
    known = {canonical(e.resource_type, e.paths, e.convert, e.value_map, e.units, [w.model_dump() for w in e.when]): e for e in base.entries}
    entries, added, extended = list(base.entries), [], []
    ids = {e.id for e in entries}
    for e in extra.entries:
        key = canonical(e.resource_type, e.paths, e.convert, e.value_map, e.units, [w.model_dump() for w in e.when])
        if key in known:
            have = known[key]
            labels = [*have.labels, *[l for l in e.labels if label_norm(l) not in {label_norm(x) for x in have.labels}]]
            if labels != have.labels:
                updated = have.model_copy(update={'labels': labels});entries[entries.index(have)] = updated;known[key] = updated;extended.append(have.id)
            continue
        if e.id in ids:raise InputError(f'ENTRY_ID_CLASH: {e.id} means a different mapping in each dictionary')
        entries.append(e);known[key] = e;ids.add(e.id);added.append(e.id)

    def words(field):
        out = {state: list(values) for state, values in getattr(base, field).items()}
        for state, values in getattr(extra, field).items():out[state] = sorted({*out.get(state, []), *values})
        return out
    merged = Dictionary(schema_version='1', state_words=words('state_words'), approval_words=words('approval_words'),
                        review_words=words('review_words'), entries=sorted(entries, key=lambda e: e.id))
    return merged, {'added': added, 'labels_added_to': sorted(set(extended))}


def load_dictionary(path):
    from .external_sheet import Dictionary
    return Dictionary.model_validate_json(Path(path).read_bytes()) if path and Path(path).is_file() else Dictionary(schema_version='1')


def promote(library, project_dictionary, promoter, entries=None, *, now=None):
    """Add approved project entries to the library dictionary, keeping the previous version and a promotion log."""
    if not promoter.strip():raise InputError('PROMOTER_REQUIRED')
    library = Path(library);library.mkdir(parents=True, exist_ok=True)
    target = library / 'dictionary.json'
    project = load_dictionary(project_dictionary)
    if entries:
        unknown = set(entries) - {e.id for e in project.entries}
        if unknown:raise InputError('UNKNOWN_ENTRY: ' + ', '.join(sorted(unknown)))
        project = project.model_copy(update={'entries': [e for e in project.entries if e.id in entries]})
    merged, report = merge(load_dictionary(target), project)
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    if target.is_file():shutil.copyfile(target, library / f"dictionary.previous-{stamp.replace(':', '').replace('-', '')}.json")
    target.write_text(json.dumps(merged.model_dump(exclude_none=True), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    log = library / 'promotions.json'
    history = json.loads(log.read_text(encoding='utf-8')) if log.is_file() else []
    history.append({'promoted_by': promoter.strip(), 'promoted_at': stamp, 'from': str(project_dictionary),
                    'from_sha256': hashlib.sha256(Path(project_dictionary).read_bytes()).hexdigest(), **report})
    log.write_text(json.dumps(history, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design library', description='Organisation library of dictionaries, policy packs and overview templates')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('list', help='policy packs and overview templates available');p.add_argument('--library')
    p = sub.add_parser('promote', help='add a project\'s approved dictionary entries to the library; the promoter is a person the user names')
    p.add_argument('--library', required=True);p.add_argument('--dictionary', required=True);p.add_argument('--promoter', required=True)
    p.add_argument('--entry', action='append', help='promote only these entry IDs')
    p = sub.add_parser('dictionary', help='the library dictionary merged with a project dictionary, for aws-design external')
    p.add_argument('--library', required=True);p.add_argument('--project');p.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'list':
            print(json.dumps({'policy_packs': available('policy-packs', args.library), 'overview_templates': available('overview-templates', args.library)},
                             ensure_ascii=False));return 0
        if args.command == 'promote':
            print(json.dumps(promote(args.library, args.dictionary, args.promoter, args.entry), ensure_ascii=False));return 0
        output = Path(args.output)
        if output.exists():raise InputError('output already exists; use a fresh path')
        merged, report = merge(load_dictionary(Path(args.library) / 'dictionary.json'), load_dictionary(args.project))
        output.write_text(json.dumps(merged.model_dump(exclude_none=True), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'output': str(output), 'entries': len(merged.entries), 'from_project': report['added']}, ensure_ascii=False));return 0
    except (InputError, OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc) if isinstance(exc, InputError) else type(exc).__name__}, ensure_ascii=False));return 2


if __name__ == '__main__':
    raise SystemExit(main())
