"""Literal string lists read from a resource property."""
from .context_values import value
from .literals import literal


def strings(ctx,resource,path):
    raw=value(ctx,resource,path)
    vals=[value(ctx,resource,path+'/'+str(i)) for i in range(len(raw))] if isinstance(raw,list) else []
    return [v for v in vals if literal(v)], not isinstance(raw,list) or any(not literal(v) for v in vals)
