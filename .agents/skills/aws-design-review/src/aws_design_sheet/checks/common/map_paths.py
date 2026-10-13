"""JSON-pointer paths of literal map keys."""
from .context_values import value
from .field_reads import ABSENT


def map_paths(ctx,resource,path):
    raw=value(ctx,resource,path)
    if raw is ABSENT:return []
    if not isinstance(raw,dict) or any(k in ('$state','Ref') or k.startswith('Fn::') or '${' in k or '{{' in k or '/' in k or '~' in k for k in raw):
        return None
    return [path+'/'+k.replace('~','~0').replace('/','~1') for k in raw]
