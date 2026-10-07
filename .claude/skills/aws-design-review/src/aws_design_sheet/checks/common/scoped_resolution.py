"""Whether a resource is resolved within a known deployment scope."""
from .literals import known_scope


def resolved(r):
    return r is not None and known_scope(r) and (r.template is None or r.template.state.value=='KNOWN')
