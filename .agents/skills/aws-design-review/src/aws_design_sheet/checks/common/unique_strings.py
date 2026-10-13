"""Uniqueness of literal strings in a nested list."""
from .context_values import value
from .literals import expand, literal


def unique_strings(ctx,resource,pattern):
    paths=list(expand(ctx,resource,pattern));values=[value(ctx,resource,p) for p in paths]
    known=[x for x in values if literal(x)]
    return 'FAIL' if len(known)!=len(set(known)) else 'NEEDS_REVIEW' if len(known)!=len(values) else 'PASS'
