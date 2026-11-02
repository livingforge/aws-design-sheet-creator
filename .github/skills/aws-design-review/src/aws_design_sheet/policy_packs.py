"""Policy packs: reusable project-policy declarations, added to an input only when a person adopts them.

A pack holds rules scoped to a resource type. `apply` writes a new input in which each
rule becomes an ordinary `project_policies` declaration for every resource of that type,
with the pack recorded as a source and a requirement. Declarations are CONFIRMED only
with the name of the person who adopted the pack; otherwise they stay UNCONFIRMED and
every result needs review. A project's own declaration for the same resource and path
wins. The input file itself is never changed.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from .delegation import is_agent

class Rule(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(pattern=r'^[a-z][a-z0-9-]{0,40}$')
    resource_type: str
    path: str
    operator: str = 'EQUALS'
    values: list[JsonValue] = Field(min_length=1)
    control: str = ''


class Pack(BaseModel):
    model_config = ConfigDict(extra='forbid')
    pack_version: str
    id: str = Field(pattern=r'^[a-z][a-z0-9-]{0,40}$')
    version: str
    title: str
    description: str
    reference: str = ''
    rules: list[Rule] = Field(min_length=1)


class InputError(ValueError):
    pass


def available(library=None):
    from .library import available as found
    return found('policy-packs', library)


def load(name, library=None):
    """A pack by path, or by name from the organisation library before the bundled packs."""
    from .library import InputError as LibraryError, find
    try:path = find('policy-packs', name, library)
    except LibraryError:raise InputError(f'UNKNOWN_PACK: {name}; available: ' + ', '.join(available(library))) from None
    raw = path.read_bytes()
    pack = Pack.model_validate_json(raw)
    if len({r.id for r in pack.rules}) != len(pack.rules):raise InputError('DUPLICATE_RULE_ID')
    # Canonical content, so line-ending conversion on checkout keeps the same hash.
    return pack, hashlib.sha256(json.dumps(pack.model_dump(mode='json'), ensure_ascii=False, sort_keys=True).encode('utf-8')).hexdigest()


def apply(design, pack, pack_sha256, *, environments=None, adopted_by=None):
    """A new input with the pack's declarations; returns (design, report)."""
    design = json.loads(json.dumps(design))
    env_ids = [e['id'] for e in design.get('environments', [])]
    scope = environments or env_ids
    if set(scope) - set(env_ids):raise InputError('UNKNOWN_ENVIRONMENT: ' + ', '.join(sorted(set(scope) - set(env_ids))))
    tag = f'pack-{pack.id}'
    used = {x.get('id') for key in ('sources', 'requirements', 'resources', 'environments', 'project_policies', 'policy_exceptions',
                                    'connections', 'operations', 'issues', 'required_inputs') for x in design.get(key, []) if isinstance(x, dict)}
    used.add(design.get('system', {}).get('id'))
    requirement = tag + '-requirement'
    if tag in used or requirement in used:raise InputError(f'PACK_ALREADY_APPLIED: {tag}')
    adopted = (adopted_by or '').strip()
    design.setdefault('sources', []).append({'id': tag, 'title': f'{pack.title} {pack.version}' + (f'（採用：{adopted}）' if adopted else '（未採用の候補）'),
                                             'locator': f'policy-pack:{pack.id}@{pack.version}#sha256={pack_sha256[:16]}'})
    design.setdefault('requirements', []).append({'id': requirement, 'title': pack.title, 'text': pack.description, 'sources': [tag]})
    own = {(p['resource_id'], p['path']) for p in design.get('project_policies', [])}
    added, skipped = [], []
    for rule in pack.rules:
        for resource in design.get('resources', []):
            if resource.get('type') != rule.resource_type:continue
            if (resource['id'], rule.path) in own:
                skipped.append({'rule': rule.id, 'resource_id': resource['id'], 'reason': 'PROJECT_DECLARATION_EXISTS'});continue
            policy_id = f"pk-{rule.id}-{hashlib.sha256(resource['id'].encode()).hexdigest()[:8]}"
            if policy_id in used:raise InputError(f'POLICY_ID_TAKEN: {policy_id}')
            used.add(policy_id)
            design.setdefault('project_policies', []).append({
                'id': policy_id, 'requirement_id': requirement, 'resource_id': resource['id'], 'path': rule.path, 'operator': rule.operator,
                'values': rule.values, 'when': [], 'environments': list(scope), 'sources': [tag],
                'confirmation': 'CONFIRMED' if adopted else 'UNCONFIRMED',
                'rationale': f'{pack.title} {pack.version} の {rule.id}' + (f'（{rule.control}）' if rule.control else '')
                             + (f'。{adopted} が案件への採用を決定。' if adopted else '。案件での採用は未決定。')})
            added.append({'policy_id': policy_id, 'rule': rule.id, 'resource_id': resource['id']})
    report = {'pack': pack.id, 'version': pack.version, 'pack_sha256': pack_sha256, 'adopted_by': adopted or None,
              'confirmation': 'CONFIRMED' if adopted else 'UNCONFIRMED', 'environments': list(scope),
              'added': added, 'skipped': skipped,
              'rules_without_resources': sorted({r.id for r in pack.rules} - {a['rule'] for a in added} - {s['rule'] for s in skipped})}
    return design, report


def main(argv=None):
    parser = argparse.ArgumentParser(prog='aws-design policy-pack', description='Add a reusable policy pack to a design input as explicit project policies')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('list', help='available packs');p.add_argument('--library', help='organisation library folder')
    p = sub.add_parser('show', help='rules of one pack');p.add_argument('pack');p.add_argument('--library')
    p = sub.add_parser('apply', help='write a new input with the pack declarations')
    p.add_argument('input');p.add_argument('--pack', required=True);p.add_argument('--output', required=True)
    p.add_argument('--environment', action='append', help='environments the declarations apply to (default: all)')
    p.add_argument('--library', help='organisation library folder')
    p.add_argument('--adopted-by', help='the person who decided to adopt the pack for this project, as the user names them')
    args = parser.parse_args(argv)
    try:
        if args.command == 'list':
            packs = [load(n, args.library)[0] for n in available(args.library)]
            print(json.dumps([{'id': x.id, 'title': x.title, 'version': x.version, 'rules': len(x.rules)} for x in packs],
                             ensure_ascii=False, indent=2));return 0
        if args.command == 'show':
            pack, digest = load(args.pack, args.library)
            print(json.dumps({**pack.model_dump(), 'sha256': digest}, ensure_ascii=False, indent=2));return 0
        import yaml
        output = Path(args.output)
        if output.exists():raise InputError('output already exists; use a fresh path')
        design = yaml.safe_load(Path(args.input).read_bytes())
        if not isinstance(design, dict) or design.get('schema_version') not in ('1.0', '1.1'):raise InputError('input must be a 1.0 or 1.1 design')
        pack, digest = load(args.pack, args.library)
        if args.adopted_by and is_agent(args.adopted_by):raise InputError('ADOPTER_IS_AGENT: agent adoption is recorded only by aws-design flow under an approved delegation policy')
        result, report = apply(design, pack, digest, environments=args.environment, adopted_by=args.adopted_by)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'output': args.output, **{k: v for k, v in report.items() if k != 'added'}, 'added': len(report['added'])}, ensure_ascii=False));return 0
    except (InputError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({'status': 'ERROR', 'message': str(exc) if isinstance(exc, InputError) else type(exc).__name__}, ensure_ascii=False));return 2
    except ValueError as exc:
        print(json.dumps({'status': 'ERROR', 'message': 'PACK_INVALID', 'detail': type(exc).__name__}));return 2


if __name__ == '__main__':
    raise SystemExit(main())
