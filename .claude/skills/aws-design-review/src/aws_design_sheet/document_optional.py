"""Optional inputs a design leaves unwritten, per resource, for people to look over.

Writable properties of the pinned schema that the effective design of one environment
does not set, at the top level and inside the objects the design writes. Properties the
required-input checklist requires are left to that checklist. This is a reference list:
it is no finding, changes no review priority and does not say a property should be set.
"""
from .document_catalog import catalog, pointer

VERSION = '1'
LIMIT = 20000
DEPTH = 32
LIMITATIONS = [
    '固定スキーマで書き込める項目のうち、この環境の設計に書かれていないもの。設定すべきという判定ではない。',
    '入れ子は設計に書いたオブジェクトの中だけを列挙する。書かれていない親の中や、未確定の値の中は列挙しない。',
    '選択肢（いずれか一方を指定する項目）や、他の項目の値によって使えない項目も区別せずに並ぶ。',
    '必要入力で必須と判定された項目は必要入力に任せ、ここには出さない。',
    'スキーマの廃止予定一覧にある項目と、説明が (Deprecated で始まる項目は除く。',
]


def _deprecated(schema):
    """Deprecated property nodes by identity and as top-level-relative patterns."""
    nodes, patterns = set(), set()
    for raw in schema.get('deprecatedProperties', ()):
        parts = [p.replace('~1', '/').replace('~0', '~') for p in raw.split('/')[1:]]
        target = schema
        for part in parts:
            target = target.get(part) if isinstance(target, dict) else None
        if isinstance(target, dict):nodes.add(id(target))
        if parts[:1] == ['properties']:
            patterns.add(pointer([p for i, p in enumerate(parts[1:]) if not (i % 2 and p == 'properties')]))
    return nodes, patterns


def _children(cat, kind, parts):
    """Named child properties of the object at parts, over every schema branch."""
    found = {}
    for node in cat.at(kind, parts):
        for branch in cat.branches(kind, node):
            for name, child in (branch.get('properties') or {}).items():found.setdefault(name, child)
    return found


def _about(cat, kind, node):
    description, default = '', None
    for branch in cat.branches(kind, node):
        description = description or branch.get('description', '')
        if default is None and 'default' in branch:default = branch['default']
    return ' '.join(description.split())[:300], default


def unwritten(document):
    env = next(e for e in document.design.environments if e.id == document.environment_id)
    required = {(r['resource_id'], r['path']) for r in document.checklist.rows if r.get('necessity') == 'REQUIRED'}
    conditional = {}
    for r in document.checklist.rows:
        if r.get('necessity') in ('NOT_APPLICABLE', 'UNKNOWN'):conditional.setdefault((r['resource_id'], r['path']), r['necessity'])
    items = {}
    for item in document.items:items.setdefault(item.resource_id, {})[item.name] = item
    rows, truncated = [], False

    def add(resource, cat, kind, parts, node, parent):
        nonlocal truncated
        path = pointer(parts)
        if (resource.id, path) in required:return
        if len(rows) >= LIMIT:truncated = True;return
        description, default = _about(cat, kind, node)
        if description.lower().startswith('(deprecated'):return
        notes = []
        pattern = pointer(['*' if isinstance(p, int) else p for p in parts])
        if pattern in creates.get(kind, ()):notes.append('作成後の変更はリソースの置き換えになる')
        if (resource.id, path) in conditional:
            notes.append({'NOT_APPLICABLE': '条件付き必須（今回の値では条件不成立）', 'UNKNOWN': '条件付き必須か未確定（必要入力を参照）'}[conditional[(resource.id, path)]])
        rows.append({'resource_id': resource.id, 'resource_type': kind, 'path': path, 'level': 'TOP' if len(parts) == 1 else 'NESTED',
                     'item_id': parent, 'description': description, 'default': default, 'notes': notes})

    def walk(resource, cat, kind, value, parts, parent, gone):
        if len(parts) > DEPTH:return
        if isinstance(value, dict) and set(value) == {'$design'}:
            inner = value['$design']
            if inner.get('mode') in ('LITERAL', 'COMPOSITE') and inner.get('status', 'DECIDED') == 'DECIDED':
                walk(resource, cat, kind, inner.get('value'), parts, parent, gone)
            return
        if isinstance(value, list):
            for index, member in enumerate(value):walk(resource, cat, kind, member, [*parts, index], parent, gone)
            return
        if not isinstance(value, dict):return
        for name, node in sorted(_children(cat, kind, parts).items()):
            child = [*parts, name]
            if name in value:walk(resource, cat, kind, value[name], child, parent, gone)
            elif not cat.readonly(kind, child) and id(node) not in gone[0] and pointer(['*' if isinstance(p, int) else p for p in child]) not in gone[1]:
                add(resource, cat, kind, child, node, parent)

    creates = {}
    for resource in document.design.resources:
        cat = catalog(document.resource_regions.get(resource.id, env.region))
        kind = resource.type;schema = cat.schemas[kind];gone = _deprecated(schema)
        creates.setdefault(kind, set(schema.get('createOnlyProperties', ())))
        written = items.get(resource.id, {})
        for name, node in sorted(cat.writable(kind).items()):
            if name in written:
                setting = written[name].expected
                if setting.status == 'DECIDED' and setting.mode in ('LITERAL', 'COMPOSITE'):
                    walk(resource, cat, kind, setting.value, [name], written[name].item_id, gone)
            elif id(node) not in gone[0] and pointer([name]) not in gone[1]:
                add(resource, cat, kind, [name], node, None)
    top = sum(r['level'] == 'TOP' for r in rows)
    return {'version': VERSION, 'environment_id': document.environment_id,
            'summary': {'rows': len(rows), 'top_level': top, 'nested': len(rows) - top,
                        'resources': len({r['resource_id'] for r in rows}), 'truncated': truncated},
            'rows': rows, 'limitations': LIMITATIONS}
