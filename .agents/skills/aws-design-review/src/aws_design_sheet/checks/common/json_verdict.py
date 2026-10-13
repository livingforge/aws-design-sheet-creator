"""Verdicts for JSON documents supplied as literal strings."""
import json


def json_verdict(raw):
    if not isinstance(raw, str) or '${' in raw or '{{' in raw or len(raw) > 256000:
        return 'NEEDS_REVIEW'
    try:
        node = json.loads(raw, parse_int=str, parse_float=str, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-JSON constant')))
    except RecursionError:
        return 'NEEDS_REVIEW'
    except ValueError:
        return 'FAIL'
    stack = [(node, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if depth > 128 or count > 10000:
            return 'NEEDS_REVIEW'
        children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
        stack.extend((child, depth+1) for child in children)
    return 'PASS'
