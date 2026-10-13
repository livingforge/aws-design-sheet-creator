"""Literal-value tests, list expansion and known deployment scope."""
import re
from .context_values import value
from .field_reads import ABSENT


def expand(ctx,resource,pattern):
    if '*' not in pattern:
        if value(ctx,resource,pattern) is not ABSENT:yield pattern
        return
    prefix,suffix=pattern.split('*',1);base=prefix.rstrip('/');items=value(ctx,resource,base)
    if isinstance(items,list):
        for i in range(len(items)):yield from expand(ctx,resource,prefix+str(i)+suffix)
    elif items is not ABSENT:yield base


def literal(s):
    return isinstance(s,str) and bool(s) and '${' not in s and '{{' not in s


def known_scope(resource):
    return bool(re.fullmatch(r'[0-9]{12}',resource.scope.account)
                and re.fullmatch(r'[a-z]+(?:-[a-z]+)+-[0-9]+',resource.scope.region))
