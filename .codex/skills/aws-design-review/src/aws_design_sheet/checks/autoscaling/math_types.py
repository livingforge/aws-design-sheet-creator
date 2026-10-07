"""Static types for an allowlisted subset of CloudWatch metric math; never eval."""
import ast
import re

PRESERVE = {'ABS', 'CEIL', 'FLOOR', 'DIFF', 'DIFF_TIME', 'LOG', 'LOG10', 'RATE', 'RUNNING_SUM'}
REDUCE = {'AVG', 'MIN', 'MAX', 'SUM', 'STDDEV', 'DATAPOINT_COUNT'}
TIMESTAMP = {'MINUTE', 'HOUR', 'DAY', 'DATE', 'MONTH', 'YEAR', 'EPOCH'}
FUNCTIONS = PRESERVE | REDUCE | TIMESTAMP | {'METRICS', 'FIRST', 'LAST', 'METRIC_COUNT', 'TIME_SERIES', 'PERIOD', 'ANOMALY_DETECTION_BAND', 'FILL', 'IF', 'SORT', 'REMOVE_EMPTY'}
KEYWORDS = {'REPEAT', 'LINEAR', 'ASC', 'DESC'}
BAD = 'INVALID_ARGUMENT_TYPE'


def parse_math(raw):
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 4096 or any(x in raw for x in ('**', '//', '${', '{{', '\\', '#')) or re.search(r',\s*[)\]]', raw):
        return None
    text = raw.strip().replace('^', '**')
    try:
        root = ast.parse(text, mode='eval').body
        nodes = list(ast.walk(root))
        function_nodes = {id(node.func) for node in nodes if isinstance(node, ast.Call)}
        keyword_nodes = set()
        for node in nodes:
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == 'FILL' and len(node.args) >= 2 and isinstance(node.args[1], ast.Name) and node.args[1].id in {'REPEAT', 'LINEAR'}:
                    keyword_nodes.add(id(node.args[1]))
                if node.func.id == 'SORT':
                    for position, allowed in ((1, REDUCE), (2, {'ASC', 'DESC'})):
                        if len(node.args) > position and isinstance(node.args[position], ast.Name) and node.args[position].id in allowed:
                            keyword_nodes.add(id(node.args[position]))
        if len(nodes) > 512:
            return None
        for node in nodes:
            if isinstance(node, ast.Call):
                if not isinstance(node.func, ast.Name) or node.func.id not in FUNCTIONS or node.keywords:
                    return None
            elif isinstance(node, ast.Name):
                if id(node) in keyword_nodes:
                    continue
                if node.id in FUNCTIONS and id(node) not in function_nodes:
                    return None
                if node.id not in FUNCTIONS and not re.fullmatch(r'[a-z][A-Za-z0-9_]*', node.id):
                    return None
            elif isinstance(node, ast.Constant):
                literal = ast.get_source_segment(text, node)
                if type(node.value) in (int, float):
                    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', literal or ''):
                        return None
                elif type(node.value) is str:
                    if not re.fullmatch(r'"[^"\r\n]*"|\x27[^\x27\r\n]*\x27', literal or ''):
                        return None
                else:
                    return None
            elif isinstance(node, ast.Compare):
                if len(node.ops) != 1:
                    return None
            elif not isinstance(node, (ast.BinOp, ast.UnaryOp, ast.List, ast.Load,
                                      ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow, ast.USub,
                                      ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq)):
                return None
        return root
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def references(root, metric_ids):
    if root is None:
        return None
    refs = {node.id for node in ast.walk(root) if isinstance(node, ast.Name) and node.id not in FUNCTIONS | KEYWORDS}
    if any(isinstance(node, ast.Call) and node.func.id == 'METRICS' for node in ast.walk(root)):
        refs.update(metric_ids)
    return refs


def infer_type(root, resolve, metric_ids, depth=0):
    if root is None or depth > 64:
        return None
    descend = lambda node: infer_type(node, resolve, metric_ids, depth + 1)
    if isinstance(root, ast.Constant):
        return 'String' if type(root.value) is str else 'S'
    if isinstance(root, ast.Name):
        if root.id in KEYWORDS:
            return root.id
        return resolve(root.id)
    if isinstance(root, ast.List):
        types = [descend(node) for node in root.elts]
        if not types or None in types:
            return None
        if BAD in types:
            return BAD
        if set(types) <= {'TS', 'TS[]'}:
            return 'TS[]'
        return 'S[]' if set(types) == {'S'} else None
    if isinstance(root, ast.UnaryOp):
        kind = descend(root.operand)
        return kind if kind in (None, BAD, 'S', 'TS', 'TS[]') else BAD
    if isinstance(root, ast.BinOp):
        types = [descend(root.left), descend(root.right)]
        if BAD in types:
            return BAD
        if None in types:
            return None
        if not set(types) <= {'S', 'TS', 'TS[]'}:
            return BAD
        if types == ['TS[]', 'TS[]']:
            return None
        return 'TS[]' if 'TS[]' in types else 'TS' if 'TS' in types else 'S'
    if isinstance(root, ast.Compare):
        kinds = [descend(root.left), descend(root.comparators[0])]
        if None in kinds:
            return None
        return ('TS' if 'TS' in kinds else 'S') if set(kinds) <= {'S', 'TS'} else BAD
    if isinstance(root, ast.Call):
        function = root.func.id
        if function == 'FILL':
            if len(root.args) != 2:
                return BAD
            first, second = [descend(argument) for argument in root.args]
            if None in (first, second):
                return None
            if first not in ('TS', 'TS[]'):
                return BAD
            if second in ('S', 'REPEAT', 'LINEAR') or first == 'TS[]' and second == 'TS':
                return first
            # The prose mentions metric fillers generally but the table lists
            # a TS filler only for TS[]; do not resolve that discrepancy here.
            return None if second in ('TS', 'String') else BAD
        if function == 'IF':
            if len(root.args) not in (2, 3):
                return BAD
            kinds = [descend(argument) for argument in root.args]
            if None in kinds:
                return None
            if not set(kinds) <= {'S', 'TS'}:
                return BAD
            if kinds[0] == 'TS' or set(kinds[1:]) == {'TS'}:
                return 'TS'
            return None
        if function == 'SORT':
            if len(root.args) not in (3, 4):
                return BAD
            first = descend(root.args[0])
            if first is None:
                return None
            if first != 'TS[]':
                return BAD
            aggregate, order = root.args[1:3]
            if not isinstance(aggregate, ast.Name) or not isinstance(order, ast.Name):
                return None
            if aggregate.id not in {'AVG', 'MIN', 'MAX', 'SUM'} or order.id not in {'ASC', 'DESC'}:
                return BAD if aggregate.id in REDUCE and order.id in {'ASC', 'DESC'} else None
            if len(root.args) == 4:
                limit = descend(root.args[3])
                if limit is None:
                    return None
                if limit != 'S':
                    return BAD
            return 'TS[]'
        if function == 'ANOMALY_DETECTION_BAND':
            if len(root.args) not in (1, 2):
                return BAD
            kinds = [descend(argument) for argument in root.args]
            if None in kinds:
                return None
            if kinds[0] != 'TS' or len(kinds) == 2 and kinds[1] != 'S':
                return BAD
            # The documented first argument is a metric ID, not arbitrary math.
            return 'TS[]' if isinstance(root.args[0], ast.Name) and root.args[0].id in metric_ids else None
        if function == 'METRICS':
            if len(root.args) > 1:
                return BAD
            if not root.args:
                return 'TS[]' if metric_ids else None
            argument = root.args[0]
            kind = descend(argument)
            if kind is None:
                return None
            if kind != 'String':
                return BAD
            return 'TS[]' if isinstance(argument, ast.Constant) and any(argument.value in name for name in metric_ids) else None
        if len(root.args) != 1:
            return BAD
        kind = descend(root.args[0])
        if kind in (None, BAD):
            return kind
        if function in PRESERVE:
            return kind if kind in ('TS', 'TS[]') else BAD
        if function in REDUCE:
            return {'TS': 'S', 'TS[]': 'TS'}.get(kind, BAD)
        if function in TIMESTAMP:
            return 'TS' if kind == 'TS' else BAD
        if function == 'REMOVE_EMPTY':
            return 'TS[]' if kind == 'TS[]' else BAD
        if function in ('FIRST', 'LAST'):
            return 'TS' if kind == 'TS[]' else BAD
        if function == 'METRIC_COUNT':
            return 'S' if kind == 'TS[]' else BAD
        if function == 'TIME_SERIES':
            return 'TS' if kind == 'S' else BAD
        if function == 'PERIOD':
            return 'S' if isinstance(root.args[0], ast.Name) and root.args[0].id in metric_ids else BAD
    return None
