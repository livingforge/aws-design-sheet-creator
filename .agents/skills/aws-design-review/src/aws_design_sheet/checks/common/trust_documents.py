"""Unique objects and unresolved values in trust policy documents."""


def unique_object(pairs):
    result = {}
    for key, val in pairs:
        if key in result:
            raise ValueError('duplicate policy key')
        result[key] = val
    return result


def unresolved(node):
    if isinstance(node, dict):
        return any(key in ('Ref','$ref','$state') or key.startswith('Fn::') or unresolved(val) for key,val in node.items())
    if isinstance(node, list):
        return any(unresolved(val) for val in node)
    return isinstance(node, str) and ('${' in node or '{{' in node)
