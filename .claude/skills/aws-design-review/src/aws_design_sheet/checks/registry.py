"""Registry of resource-level design checks.

A check module registers each check with ``@resource_check(...)`` and lists the
documentation behind its rules in a module-level ``SOURCES`` dict.  The checker
runs every check registered for a resource's type.
"""
import importlib
import inspect
import pkgutil

_CHECKS = []
_LOADED = False
_BY_TYPE = {}  # resource type -> registered entries for it, in registration order
_INDEXED = 0  # len(_CHECKS) when _BY_TYPE was built


def resource_check(*types, when=None):
    """Register ``fn(design, resource)`` for the given resource types.

    ``types`` are exact CloudFormation types or ``AWS::Service::*`` wildcards;
    without types the check runs for every resource.  ``when(design, resource)``
    further limits when the check runs.  A check returns one finding or a list.
    """
    exact = frozenset(t for t in types if not t.endswith('::*'))
    prefixes = tuple(t[:-1] for t in types if t.endswith('::*'))

    def register(fn):
        resource_only = list(inspect.signature(fn).parameters)[:1] == ['resource']
        _CHECKS.append((exact, prefixes, bool(types), when, fn, resource_only))
        return fn
    return register


def _applies(entry, design, resource):
    exact, prefixes, typed, when, _, _ = entry
    if typed and resource.type not in exact and not resource.type.startswith(prefixes):
        return False
    return when is None or when(design, resource)


def _for_type(type_name):
    """Entries whose types cover type_name; rebuilt when checks are registered."""
    global _INDEXED
    if _INDEXED != len(_CHECKS):
        _BY_TYPE.clear()
        _INDEXED = len(_CHECKS)
    if type_name not in _BY_TYPE:
        _BY_TYPE[type_name] = [entry for entry in _CHECKS if not entry[2] or type_name in entry[0]
                               or type_name.startswith(entry[1])]
    return _BY_TYPE[type_name]


def _run(entry, design, resource):
    fn, resource_only = entry[4], entry[5]
    found = fn(resource) if resource_only else fn(design, resource)
    return [found] if isinstance(found, dict) else list(found)


def check_modules():
    """Import every check module so that its checks are registered."""
    global _LOADED
    package = importlib.import_module(__package__)
    modules = []
    for info in pkgutil.walk_packages(package.__path__, __package__ + '.'):
        modules.append(importlib.import_module(info.name))
    _LOADED = True
    return modules


def run_resource_checks(design, resource):
    """Findings of every registered check that applies to the resource."""
    if not _LOADED:
        check_modules()
    findings = []
    for entry in _for_type(resource.type):
        if entry[3] is None or entry[3](design, resource):
            findings.extend(_run(entry, design, resource))
    return findings


def combine(*checks):
    """One check running the given registered checks, as the checker would."""
    entries = [entry for entry in _CHECKS if entry[4] in checks]
    missing = set(checks) - {entry[4] for entry in entries}
    if missing:
        raise ValueError(f'unregistered checks: {sorted(fn.__name__ for fn in missing)}')

    def run(design, resource):
        findings = []
        for entry in entries:
            if _applies(entry, design, resource):
                findings.extend(_run(entry, design, resource))
        return findings
    return run


def rule_sources():
    """Merged ``SOURCES`` of all check modules: rule ID -> documentation URLs."""
    merged = {}
    for module in check_modules():
        merged.update(getattr(module, 'SOURCES', {}))
    return merged
