"""Bounded, three-valued required-input inspection, independent of CFN equality.

This is not a replacement for cfn-lint or an AWS policy evaluator. Schema
assertions are used only to select required-input branches. Unknown selection
never becomes an exemption or a successful completeness verdict.
"""
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json

import regex
from cfnlint.jsonschema import StandardValidator
from cfnlint.version import __version__ as CFN_LINT_VERSION

from .document_catalog import catalog, pointer, token
from .document_requirements import Checklist


@dataclass(frozen=True)
class Unknown:
    state: str


MISSING = Unknown('MISSING')
TRUE, FALSE, UNKNOWN = 'TRUE', 'FALSE', 'UNKNOWN'


def tri_and(values):
    values = list(values)
    return False if False in values else None if None in values else True


def tri_or(values):
    values = list(values)
    return True if True in values else None if None in values else False


def presence(value):
    if isinstance(value, Unknown):
        if value.state in ('MISSING', 'OMITTED', 'NOT_APPLICABLE'): return False
        if value.state in ('INTERNAL_REFERENCE', 'EXTERNAL_REFERENCE', 'SECRET_REFERENCE'): return True
        return None
    return True


def resolved(value):
    if isinstance(value, Unknown): return False
    if isinstance(value, dict): return all(resolved(v) for v in value.values())
    if isinstance(value, list): return all(resolved(v) for v in value)
    return True


def setting_value(setting):
    if setting.status != 'DECIDED': return Unknown(setting.status)
    modes = {'DEFAULT': 'DEFAULT_REQUESTED', 'OMITTED': 'OMITTED',
             'RESOURCE_REF': 'INTERNAL_REFERENCE', 'EXTERNAL_REF': 'EXTERNAL_REFERENCE',
             'SECRET_REF': 'SECRET_REFERENCE', 'EXPRESSION': 'EXPRESSION_UNRESOLVED'}
    if setting.mode in modes: return Unknown(modes[setting.mode])
    if setting.mode == 'LITERAL': return setting.value
    from .document_v11 import SchemaSetting
    def walk(value):
        if isinstance(value, dict):
            if set(value) == {'$design'}:
                return setting_value(SchemaSetting.model_validate(value['$design']))
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list): return [walk(v) for v in value]
        return value
    return walk(setting.value)


def child(value, key):
    if isinstance(value, Unknown):
        return MISSING if presence(value) is False else Unknown('PARENT_UNRESOLVED')
    if isinstance(value, dict): return value.get(str(key), MISSING)
    if isinstance(value, list) and isinstance(key, int) and 0 <= key < len(value): return value[key]
    return MISSING


def state(value):
    if isinstance(value, Unknown): return value.state
    if value is None: return 'NULL'
    if isinstance(value, str) and not value.strip(): return 'EMPTY'
    if isinstance(value, (list, dict)) and not value: return 'EMPTY'
    return 'VALUE' if resolved(value) else 'PARTIAL'


def local_ref(root, ref):
    if not isinstance(ref, str) or not ref.startswith('#/'): raise ValueError('non-local reference')
    value = root
    for part in ref[2:].split('/'): value = value[part.replace('~1', '/').replace('~0', '~')]
    return value


ANNOTATIONS = {'title', 'description', '$comment', '$id', '$schema', 'definitions', '$defs',
               'default', 'examples', 'readOnly', 'writeOnly', 'typeName', 'documentationUrl',
               'sourceUrl', 'handlers', 'tagging', 'readOnlyProperties', 'writeOnlyProperties',
               'createOnlyProperties', 'conditionalCreateOnlyProperties', 'primaryIdentifier',
               'additionalIdentifiers', 'replacementStrategy', 'deprecatedProperties'}
ATOMIC = {'type', 'const', 'enum', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum',
          'multipleOf', 'minLength', 'maxLength', 'minItems', 'maxItems', 'minProperties',
          'maxProperties', 'uniqueItems'}


def predicate(schema, value, root=None, depth=0):
    """Kleene logic; only supported assertions can prove a branch true/false."""
    root = schema if root is None else root
    if depth > 32: return None
    if isinstance(schema, bool): return schema
    if not isinstance(schema, dict): return None
    if not schema: return True
    if isinstance(value, dict):
        value = {k: v for k, v in value.items() if presence(v) is not False}
    outcomes = []
    def evaluate(s, v=value): return predicate(s, v, root, depth + 1)
    try:
        for key, arg in schema.items():
            if key in ANNOTATIONS: continue
            if key == '$ref': outcomes.append(evaluate(local_ref(root, arg)))
            elif key == 'type':
                types = arg if isinstance(arg, list) else [arg]
                checks = {'object': lambda: isinstance(value, dict), 'array': lambda: isinstance(value, list),
                          'string': lambda: isinstance(value, str), 'boolean': lambda: type(value) is bool,
                          'integer': lambda: type(value) is int, 'number': lambda: type(value) in (int, float),
                          'null': lambda: value is None}
                outcomes.append(None if isinstance(value, Unknown) or any(t not in checks for t in types)
                                else any(checks[t]() for t in types))
            elif key in ('minItems', 'maxItems', 'minProperties', 'maxProperties'):
                expected_type = list if key.endswith('Items') else dict
                if isinstance(value, Unknown): outcomes.append(None)
                elif not isinstance(value, expected_type): outcomes.append(True)
                elif any(presence(v) is None for v in (value.values() if isinstance(value, dict) else value)):
                    outcomes.append(None)
                else: outcomes.append(len(value) >= arg if key.startswith('min') else len(value) <= arg)
            elif key in ATOMIC:
                # Structural length/type is known even if a child is unknown.
                structural = key in {'type', 'minItems', 'maxItems', 'minProperties', 'maxProperties'}
                known = not isinstance(value, Unknown) if structural else resolved(value)
                if key in ('minProperties', 'maxProperties') and isinstance(value, dict) and any(presence(v) is None for v in value.values()): known = False
                outcomes.append(StandardValidator({key: arg}).is_valid(value) if known else None)
            elif key == 'pattern':
                outcomes.append(None if not resolved(value) else
                                bool(regex.search(arg, value, timeout=.05)) if isinstance(value, str) else True)
            elif key == 'required':
                outcomes.append(tri_and(presence(child(value, k)) for k in arg)
                                if isinstance(value, (dict, Unknown)) else True)
            elif key == 'properties':
                if isinstance(value, Unknown): outcomes.append(None)
                elif isinstance(value, dict):
                    outcomes.append(tri_and(evaluate(s, value[k]) for k, s in arg.items() if k in value
                                            and presence(value[k]) is not False))
            elif key in ('allOf', 'anyOf', 'oneOf'):
                vals = [evaluate(s) for s in arg]
                if key == 'allOf': outcomes.append(tri_and(vals))
                elif key == 'anyOf': outcomes.append(tri_or(vals))
                else: outcomes.append(False if vals.count(True) > 1 else None if None in vals else vals.count(True) == 1)
            elif key == 'not':
                val = evaluate(arg); outcomes.append(None if val is None else not val)
            elif key == 'if':
                val = evaluate(arg)
                yes, no = evaluate(schema.get('then', True)), evaluate(schema.get('else', True))
                outcomes.append(yes if val is True else no if val is False else yes if yes == no else None)
            elif key in ('then', 'else', 'additionalItems'): continue
            elif key in ('dependencies', 'dependentRequired'):
                for name, dep in arg.items():
                    active = presence(child(value, name))
                    result = evaluate({'required': dep} if isinstance(dep, list) else dep)
                    outcomes.append(True if active is False else result if active is True else True if result is True else None)
            elif key in ('requiredOr', 'requiredXor'):
                vals = [presence(child(value, k)) for k in arg]
                outcomes.append(tri_or(vals) if key == 'requiredOr' else
                                False if vals.count(True) > 1 else None if None in vals else vals.count(True) == 1)
            elif key in ('items', 'prefixItems'):
                if isinstance(value, Unknown): outcomes.append(None)
                elif isinstance(value, list):
                    if isinstance(arg, list):
                        outcomes.append(tri_and(evaluate(arg[i] if i < len(arg) else schema.get('additionalItems', True), v)
                                                for i, v in enumerate(value)))
                    else: outcomes.append(tri_and(evaluate(arg, v) for v in value))
            elif key == 'contains':
                outcomes.append(tri_or(evaluate(arg, v) for v in value) if isinstance(value, list)
                                else None if isinstance(value, Unknown) else True)
            elif key in ('patternProperties', 'additionalProperties'):
                if isinstance(value, Unknown): outcomes.append(None)
                elif isinstance(value, dict):
                    patterns = schema.get('patternProperties', {})
                    for name, v in value.items():
                        if presence(v) is False: continue
                        if isinstance(v, Unknown) and v.state == 'READ_ONLY': continue
                        matched = [s for p, s in patterns.items() if regex.search(p, name, timeout=.05)]
                        if key == 'patternProperties': outcomes.extend(evaluate(s, v) for s in matched)
                        elif not matched and name not in schema.get('properties', {}): outcomes.append(evaluate(arg, v))
            else:
                # Includes formats, CFN-specific functions and new schema keywords.
                outcomes.append(None)
    except (KeyError, TypeError, ValueError, RecursionError, TimeoutError):
        return None
    return tri_and(outcomes)


def has_requirements(schema):
    """Predicate-only required keywords are not themselves obligations."""
    if not isinstance(schema, dict): return False
    if any(k in schema for k in ('required', 'dependencies', 'dependentRequired', 'requiredOr', 'requiredXor')): return True
    for k in ('allOf', 'anyOf', 'oneOf'):
        if any(has_requirements(s) for s in schema.get(k, [])): return True
    for k in ('then', 'else', 'items', 'additionalProperties'):
        if has_requirements(schema.get(k)): return True
    return any(has_requirements(s) for s in schema.get('properties', {}).values())


@lru_cache(maxsize=1)
def extensions():
    """Reuse installed cfn-lint error schemas at their registered property paths.

    Python rules, recommendations and non-resource rules are not converted to
    requirements. This deliberately avoids inferring scope from file names.
    """
    from cfnlint.core import get_rules
    from cfnlint.rules.jsonschema.CfnLintJsonSchema import CfnLintJsonSchema
    found = {}
    for rule in get_rules([], [], ['E']):
        if not isinstance(rule, CfnLintJsonSchema) or not rule.id.startswith('E') or not has_requirements(rule.schema): continue
        for key in rule.keywords:
            parts = key.split('/')
            if len(parts) < 3 or parts[0] != 'Resources' or parts[2] != 'Properties' or not parts[1].startswith('AWS::'): continue
            if any(p in ('*', '**') for p in parts[3:]): continue
            digest = hashlib.sha256(json.dumps(rule.schema, sort_keys=True).encode()).hexdigest()
            found.setdefault(parts[1], []).append((parts[3:], rule.schema,
                {'provider': 'cfn-lint', 'version': CFN_LINT_VERSION, 'rule_id': rule.id,
                 'schema_sha256': digest, 'source': getattr(rule, 'source_url', '') or 'UNKNOWN',
                 'adapter_required': type(rule).validate is not CfnLintJsonSchema.validate
                                     or type(rule)._iter_errors is not CfnLintJsonSchema._iter_errors}))
    return found


class Inspector:
    def __init__(self, document, cat=None, include_extensions=True):
        self.document = document
        self.cat = cat or catalog()
        self.include_extensions = include_extensions
        self.rows = []
        self.exclusions = set()
        self.env = next(e for e in document.design.environments if e.id == document.environment_id)
        self.region_matches = getattr(self.env, 'region', self.cat.manifest['region']) == self.cat.manifest['region']
        self.overrides = {o.resource_id: o.settings for o in self.env.overrides}
        self.sources = {s.id: s.model_dump() for s in document.design.sources}
        self.seen = set()
        self.limit_hit = False

    def condition_value(self, resource, value, parts=(), depth=0):
        """Read-only outputs are unavailable, not absent design decisions."""
        if depth > 32 or self.cat.readonly(resource.type, parts): return Unknown('READ_ONLY')
        if isinstance(value, list):
            return [self.condition_value(resource, v, [*parts, i], depth + 1) for i, v in enumerate(value)]
        if not isinstance(value, dict): return value
        result = {k: self.condition_value(resource, v, [*parts, k], depth + 1) for k, v in value.items()}
        for path in self.cat.schemas[resource.type].get('readOnlyProperties', []):
            wanted = [p.replace('~1', '/').replace('~0', '~') for p in path.split('/')[2:]]
            if len(wanted) == len(parts) + 1 and all(a == '*' or a == str(b) for a, b in zip(wanted, parts)):
                result[wanted[-1]] = Unknown('READ_ONLY')
        return result

    def add(self, resource, parts, kind, active, condition, schema_pointer, source, value,
            *, result=None, detail='', requirement=None, default_nodes=(), default_pointer=None):
        path = pointer(parts) if parts else '/properties'
        if parts and self.cat.readonly(resource.type, parts):
            self.exclusions.add(resource.id + path); return
        key = (resource.id, path, kind, schema_pointer, source.get('rule_id'), requirement.id if requirement else None, condition)
        if key in self.seen: return
        self.seen.add(key)
        if len(self.rows) >= 10000:
            self.limit_hit = True; return
        input_state = state(value)
        default_evidence = [{'provider': 'pinned-cfn-schema', 'zip_sha256': self.cat.manifest['zip_sha256'],
                             'schema_pointer': default_pointer or '#' + path + '/default'}
                            for n in default_nodes if isinstance(n, dict) and 'default' in n]
        if active is False: result = 'NOT_APPLICABLE'
        elif active is None: result = 'NEEDS_REVIEW'
        elif result is None:
            if input_state in ('MISSING', 'OMITTED', 'NOT_APPLICABLE'): result = 'MISSING'
            elif input_state == 'VALUE': result = 'SATISFIED'
            elif input_state == 'INTERNAL_REFERENCE': result = 'SATISFIED_REFERENCE'
            elif (input_state == 'DEFAULT_REQUESTED' and requirement and requirement.allow_documented_default
                  and default_evidence): result = 'SATISFIED_DEFAULT'
            else: result = 'NEEDS_REVIEW'
        necessity = active
        if requirement and (requirement.confirmation != 'CONFIRMED' or not requirement.sources):
            # An unconfirmed interpretation cannot fail the user's input.
            if active is not False:
                result = 'NEEDS_REVIEW'; necessity = None
        actions = {'MISSING': '必要な値・参照を入力する。明示省略・適用外でAWS必須を免除できません。',
                   'NEEDS_REVIEW': '条件・未決定値・参照または根拠を確認して再生成する。',
                   'SATISFIED': '入力の充足のみ確認済み。値の妥当性・要件の期待値一致は別検査。',
                   'SATISFIED_REFERENCE': '内部参照先は入力内に存在。参照先の実値・配置は未検証。',
                   'SATISFIED_DEFAULT': '案件が明示許可したスキーマ既定値。AWS必須や実値解決の保証ではありません。',
                   'NOT_APPLICABLE': '条件不成立または対象環境外。適用条件の変更時に再確認する。',
                   'BRANCH_CONFLICT': '選択肢の必要条件を満たす構成に修正する。複数分岐を一律必須にはしません。'}
        top = parts[0] if parts else '@branch'
        setting = {**resource.settings, **self.overrides.get(resource.id, {})}.get(top)
        selected_setting = setting
        if setting and setting.mode == 'COMPOSITE':
            nested = setting.value
            for part in parts[1:]:
                nested = child(nested, part)
            if isinstance(nested, dict) and set(nested) == {'$design'}:
                from .document_v11 import SchemaSetting
                selected_setting = SchemaSetting.model_validate(nested['$design'])
        input_sources = [self.sources[s] for s in selected_setting.sources] if selected_setting else []
        index = self.document.design.resources.index(resource)
        input_pointer = '/resources/' + str(index) + '/settings/' + token(str(top))
        if not parts: input_pointer = '/resources/' + str(index) + '/settings'
        if top in self.overrides.get(resource.id, {}):
            override = next(i for i, o in enumerate(self.env.overrides) if o.resource_id == resource.id)
            env_index = self.document.design.environments.index(self.env)
            input_pointer = f'/environments/{env_index}/overrides/{override}/settings/' + token(str(top))
        evidence = [self.sources[s] for s in requirement.sources] if requirement else [source]
        identity = json.dumps(key, ensure_ascii=False, sort_keys=True)
        self.rows.append({'checklist_id': resource.id + '.required-' + hashlib.sha256(identity.encode()).hexdigest()[:16],
            'item_id': resource.id + '.' + str(top), 'resource_id': resource.id, 'resource_type': resource.type,
            'input_pointer': input_pointer, 'input_pointer_exists': not parts or setting is not None,
            'path': path, 'requirement_kind': kind, 'necessity': {True: 'REQUIRED', False: 'NOT_APPLICABLE', None: 'UNDETERMINED'}[necessity],
            'condition_result': {True: TRUE, False: FALSE, None: UNKNOWN}[active], 'condition': condition,
            'schema_pointer': schema_pointer, 'requirement_id': requirement.requirement_id if requirement else None,
            'requirement_confirmation': requirement.confirmation if requirement else 'SCHEMA_DEFINED',
            'evidence': evidence or [{'source': 'UNKNOWN'}], 'input_sources': input_sources or [{'source': 'UNKNOWN'}],
            'input_state': input_state, 'value_resolution': 'RESOLVED' if resolved(value) else 'UNRESOLVED',
            'result': result, 'detail': detail, 'default_evidence': default_evidence, 'action': actions[result],
            'environment': self.env.id})

    def inspect_schema(self, resource, tree, schema, source, base=()):
        root = schema
        def obligations(node, parts, seen=()):
            if not isinstance(node, dict) or id(node) in seen: return False
            seen = (*seen, id(node))
            if any(not self.cat.readonly(resource.type, [*parts, n]) for n in node.get('required', [])): return True
            if '$ref' in node:
                try:
                    if obligations(local_ref(root, node['$ref']), parts, seen): return True
                except (ValueError, KeyError, TypeError): return True
            for key in ('dependencies', 'dependentRequired', 'requiredOr', 'requiredXor'):
                if key in node: return True
            for key in ('allOf', 'anyOf', 'oneOf'):
                if any(obligations(s, parts, seen) for s in node.get(key, [])): return True
            for key in ('then', 'else'):
                if obligations(node.get(key), parts, seen): return True
            if any(obligations(s, [*parts, n], seen) for n, s in node.get('properties', {}).items()): return True
            items = node.get('items', [])
            return any(obligations(s, [*parts, '*'], seen) for s in (items if isinstance(items, list) else [items]))
        def walk(node, value, parts, loc, active=True, condition='always', conditional=False, trail=()):
            if self.limit_hit: return
            if len(trail) > 32 or (id(node), tuple(parts)) in trail:
                self.add(resource, parts, 'SCHEMA_REVIEW', None, condition, loc, source, value, detail='Recursive schema traversal not completed.'); return
            if not isinstance(node, dict): return
            trail = (*trail, (id(node), tuple(parts)))
            kind = 'AWS_CONDITIONAL' if conditional else 'AWS_REQUIRED'
            if '$ref' in node:
                try: target = local_ref(root, node['$ref'])
                except (ValueError, KeyError, TypeError):
                    self.add(resource, parts, 'SCHEMA_REVIEW', None, condition, loc, source, value, detail='Unsupported schema reference.'); return
                walk(target, value, parts, node['$ref'], active, condition, conditional, trail)
            for index, name in enumerate(node.get('required', [])):
                prop = node.get('properties', {}).get(name, {})
                self.add(resource, [*parts, name], kind, active, condition, loc + '/required/' + str(index),
                         source, child(value, name), default_nodes=[prop], default_pointer=loc + '/properties/' + token(name) + '/default')
            for index, branch in enumerate(node.get('allOf', [])):
                walk(branch, value, parts, loc + '/allOf/' + str(index), active, condition, conditional, trail)
            if 'if' in node:
                selected = predicate(node['if'], self.condition_value(resource, value, parts), root)
                test = json.dumps(node['if'], ensure_ascii=False, sort_keys=True)
                for key, choice in [('then', selected), ('else', None if selected is None else not selected)]:
                    if key in node:
                        walk(node[key], value, parts, loc + '/' + key, tri_and([active, choice]),
                             condition + '; ' + ('if ' if key == 'then' else 'unless ') + test, True, trail)
            for keyword in ('anyOf', 'oneOf', 'requiredOr', 'requiredXor'):
                if keyword not in node: continue
                branches = node[keyword]
                if keyword.startswith('required'): branches = [{'required': [k]} for k in branches]
                if not any(obligations(branch, parts) for branch in branches): continue
                vals = [predicate(branch, self.condition_value(resource, value, parts), root) for branch in branches]
                exclusive = keyword in ('oneOf', 'requiredXor')
                ok = (False if vals.count(True) > 1 else None if None in vals else vals.count(True) == 1) if exclusive else tri_or(vals)
                label = condition + '; ' + keyword + ' selection'
                self.add(resource, parts, 'AWS_CONDITIONAL', active, label, loc + '/' + keyword, source, value,
                         result='SATISFIED' if ok is True else 'BRANCH_CONFLICT' if ok is False else 'NEEDS_REVIEW',
                         detail='Branch matches: ' + ','.join({True: TRUE, False: FALSE, None: UNKNOWN}[v] for v in vals))
                for index, branch in enumerate(branches):
                    # No valid branch does NOT make all alternatives mandatory.
                    choice = vals[index] if ok is True else None
                    if keyword.startswith('required'):
                        name = branch['required'][0]
                        self.add(resource, [*parts, name], 'AWS_CONDITIONAL', tri_and([active, choice]), label,
                                 loc + '/' + keyword + '/' + str(index), source, child(value, name))
                        continue
                    walk(branch, value, parts, loc + '/' + keyword + '/' + str(index), tri_and([active, choice]), label, True, trail)
            for keyword in ('dependencies', 'dependentRequired'):
                for name, dependency in node.get(keyword, {}).items():
                    choice = presence(child(self.condition_value(resource, value, parts), name))
                    if isinstance(dependency, list):
                        for index, required in enumerate(dependency):
                            self.add(resource, [*parts, required], 'AWS_CONDITIONAL', tri_and([active, choice]),
                                     condition + '; present ' + pointer([*parts, name]),
                                     loc + '/' + keyword + '/' + token(name) + '/' + str(index), source, child(value, required))
                        continue
                    branch = {'required': dependency} if isinstance(dependency, list) else dependency
                    walk(branch, value, parts, loc + '/' + keyword + '/' + token(name), tri_and([active, choice]),
                         condition + '; present ' + pointer([*parts, name]), True, trail)
            # Required nested members are checked for selected objects/arrays.
            # Absent parents get their own obligation; don't fabricate instances.
            for name, prop in node.get('properties', {}).items():
                if isinstance(value, Unknown):
                    # The opaque parent is the review boundary. Inventing every
                    # optional descendant produces misleading denominators and
                    # can expand recursive schemas without any input instance.
                    if has_requirements(prop):
                        self.add(resource, parts, 'SCHEMA_REVIEW', None, condition, loc + '/properties', source, value,
                                 detail='Opaque parent: nested optional objects cannot be inspected until its value is supplied.')
                    continue
                v = child(value, name)
                if presence(v) is False or self.cat.readonly(resource.type, [*parts, name]): continue
                walk(prop, v, [*parts, name], loc + '/properties/' + token(name),
                     tri_and([active, presence(v)]), condition + '; parent ' + pointer([*parts, name]), True, trail)
            patterns = node.get('patternProperties', {})
            if isinstance(value, dict):
                for name, v in value.items():
                    matched = []
                    for pattern, prop in patterns.items():
                        try:
                            if regex.search(pattern, name, timeout=.05): matched.append((pattern, prop))
                        except (regex.error, TimeoutError):
                            self.add(resource, parts, 'SCHEMA_REVIEW', None, condition, loc, source, value, detail='Pattern traversal unresolved.')
                    for pattern, prop in matched:
                        walk(prop, v, [*parts, name], loc + '/patternProperties/' + token(pattern), active, condition, conditional, trail)
                    additional = node.get('additionalProperties')
                    if name not in node.get('properties', {}) and not matched and isinstance(additional, dict):
                        walk(additional, v, [*parts, name], loc + '/additionalProperties', active, condition, conditional, trail)
            items = node.get('prefixItems', node.get('items'))
            if items is not None:
                vals = list(enumerate(value)) if isinstance(value, list) else (
                    [(i, Unknown('PARENT_UNRESOLVED')) for i in range(len(items))] if isinstance(items, list)
                    else [('*', Unknown('PARENT_UNRESOLVED'))]) if isinstance(value, Unknown) else []
                for index, v in vals:
                    prop = (items[index] if isinstance(index, int) and index < len(items) else node.get('additionalItems', True)) if isinstance(items, list) else items
                    item_loc = loc + ('/prefixItems' if 'prefixItems' in node else '/items')
                    if isinstance(items, list): item_loc = item_loc + '/' + str(index) if isinstance(index, int) and index < len(items) else loc + '/additionalItems'
                    walk(prop, v, [*parts, index], item_loc, tri_and([active, None if isinstance(value, Unknown) else True]), condition, conditional, trail)
            # These can contain requirements, but cannot safely be flattened into
            # per-member obligations. Surface the incomplete traversal explicitly.
            for keyword in ('contains', 'not', 'dependentSchemas', 'unevaluatedProperties', 'unevaluatedItems'):
                if keyword in node and has_requirements(node[keyword]):
                    self.add(resource, parts, 'SCHEMA_REVIEW', None, condition, loc + '/' + keyword, source, value,
                             detail='Required-input traversal does not interpret ' + keyword)
        value = tree
        for key in base: value = child(value, key)
        if base and presence(value) is False: return
        walk(schema, value, list(base), '#', True if self.region_matches else None,
             'always' if self.region_matches else 'region differs from pinned schema; applicability unknown',
             source.get('provider') == 'cfn-lint')

    def project(self, resource, tree, req):
        active = self.env.id in req.environments if req.environments else True
        test = predicate(req.when, self.condition_value(resource, tree)) if req.when is not None else True
        active = tri_and([active, test])
        parts = [p.replace('~1', '/').replace('~0', '~') for p in req.path.split('/')[2:]]
        paths = [([], tree)]
        for part in parts:
            next_paths = []
            for path, value in paths:
                if part == '*':
                    if isinstance(value, list) and value:
                        next_paths.extend(([*path, i], v) for i, v in enumerate(value))
                    else: next_paths.append(([*path, '*'], Unknown('PARENT_UNRESOLVED') if presence(value) is not False else MISSING))
                else:
                    key = int(part) if part.isdigit() else part
                    next_paths.append(([*path, key], child(value, key)))
            paths = next_paths
        for path, value in paths:
            self.add(resource, path, 'PROJECT_REQUIRED', active,
                     json.dumps({'environments': req.environments or 'all', 'when': req.when}, ensure_ascii=False, sort_keys=True),
                     'project:' + req.id, {'source': 'explicit project declaration'}, value,
                     requirement=req, detail=req.rationale,
                     default_nodes=[self.cat.schemas[resource.type].get('properties', {}).get(path[0], {})]
                     if len(path) == 1 else [])

    def run(self):
        for resource in self.document.design.resources:
            settings = {**resource.settings, **self.overrides.get(resource.id, {})}
            tree = {k: setting_value(v) for k, v in settings.items()}
            source = {'provider': 'pinned-cfn-schema', 'resource_type': resource.type,
                      **{k: self.cat.manifest[k] for k in ('region', 'retrieved_at', 'source', 'zip_sha256')}}
            if not self.region_matches:
                self.add(resource, [], 'SCHEMA_REVIEW', None, 'region differs from pinned schema', '#', source,
                         Unknown('NOT_INSPECTED'), detail='Use a matching schema snapshot. No regional applicability inferred.')
            self.inspect_schema(resource, tree, self.cat.schemas[resource.type], source)
            if self.include_extensions:
                for base, schema, origin in extensions().get(resource.type, []):
                    if origin['adapter_required']:
                        self.add(resource, base, 'SCHEMA_REVIEW', None, 'cfn-lint custom preprocessing', '#', origin,
                                 Unknown('NOT_INSPECTED'), detail='This rule has custom preprocessing; its internal JSON schema is not applied at the resource root.')
                    else: self.inspect_schema(resource, tree, schema, origin, base)
            for req in self.document.design.required_inputs:
                if req.resource_id == resource.id: self.project(resource, tree, req)
        counts = Counter(r['result'] for r in self.rows)
        active = sum(r['necessity'] == 'REQUIRED' for r in self.rows)
        unknown = sum(r['condition_result'] == 'UNKNOWN' for r in self.rows)
        missing = counts['MISSING'] + counts['BRANCH_CONFLICT']
        status = 'INCOMPLETE' if missing else 'NEEDS_REVIEW' if counts['NEEDS_REVIEW'] or self.limit_hit else 'SATISFIED_WITHIN_SCOPE' if self.rows else 'NO_REQUIREMENTS_IDENTIFIED'
        return Checklist(status=status, rows=self.rows, summary={
            'obligations_total': len(self.rows), 'active_denominator': active, 'condition_unknown': unknown,
            'necessity_unknown': sum(r['necessity'] == 'UNDETERMINED' for r in self.rows),
            'not_applicable': counts['NOT_APPLICABLE'], 'missing_or_conflicting': missing,
            'needs_review': counts['NEEDS_REVIEW'], 'results': dict(sorted(counts.items())),
            'by_kind': dict(sorted(Counter(r['requirement_kind'] for r in self.rows).items())),
            'unique_input_paths': len({(r['resource_id'], r['path']) for r in self.rows}),
            'read_only_excluded': len(self.exclusions), 'traversal_limit_reached': self.limit_hit,
            'denominator_definition': 'obligation rows, not all catalog properties; different reasons can target one input path'},
            provenance={'pinned_schema_sha256': self.cat.manifest['zip_sha256'], 'cfn_lint_version': CFN_LINT_VERSION,
                        'input_sha256': self.document.input_sha256},
            limitations=[
                'AWS conditions absent from the pinned schemas or registered cfn-lint error JSON schemas are not covered.',
                'Python cfn-lint rules, warning policies and general enum/range/value correctness are not completeness checks.',
                'No CFN values, defaults, external values or secrets are imported to fill missing design inputs.',
                'Literal null/empty inputs require review (not automatically invalid under AWS); false and zero are filled inputs. Child obligations remain independent.',
                'Source prose is not interpreted. Project predicates and confirmation are explicit declarations.',
                'SATISFIED_WITHIN_SCOPE is not design approval; no global AWS completeness percentage is claimed.',
                'Traversal is bounded to 32 schema steps and 10000 obligations; unresolved branches remain review items.'])


def attach(document):
    document.checklist = Inspector(document).run()
    from .document_policy import evaluate
    document.project_policy = evaluate(document)
    return document
