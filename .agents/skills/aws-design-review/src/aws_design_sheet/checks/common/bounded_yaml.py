"""Bounded, data-only YAML parsing: no tags, anchors, expressions or files."""
import yaml
from yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent, DocumentStartEvent
from yaml.nodes import MappingNode, ScalarNode, SequenceNode
from .literals import literal


def bounded_yaml(raw):
    """Retain scalar strings to avoid YAML 1.1 implicit bool/date coercion."""
    if not literal(raw) or len(raw) > 256000:
        return 'NEEDS_REVIEW', None
    try:
        depth = documents = 0
        for count, event in enumerate(yaml.parse(raw, Loader=yaml.BaseLoader)):
            if count > 10000 or isinstance(event, AliasEvent) or getattr(event, 'tag', None):
                return 'NEEDS_REVIEW', None
            if isinstance(event, DocumentStartEvent):
                documents += 1
                if documents > 1:
                    return 'NEEDS_REVIEW', None
            if isinstance(event, CollectionStartEvent):
                depth += 1
                if depth > 64:
                    return 'NEEDS_REVIEW', None
            if isinstance(event, CollectionEndEvent):
                depth -= 1
        root = yaml.compose(raw, Loader=yaml.BaseLoader)
        def convert(node):
            if isinstance(node, ScalarNode):
                return node.value
            if isinstance(node, SequenceNode):
                return [convert(n) for n in node.value]
            if isinstance(node, MappingNode):
                result = {}
                for key, val in node.value:
                    if not isinstance(key, ScalarNode) or key.value in result:
                        raise LookupError
                    result[key.value] = convert(val)
                return result
            raise LookupError
        return 'PASS', convert(root)
    except (LookupError, RecursionError, UnicodeError):
        return 'NEEDS_REVIEW', None
    except yaml.YAMLError:
        return 'FAIL', None
