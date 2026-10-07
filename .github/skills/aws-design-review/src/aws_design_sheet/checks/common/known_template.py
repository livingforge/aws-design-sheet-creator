"""Whether a resource comes from a template whose state is known."""


def resolved(r):
    return r is not None and (r.template is None or r.template.state.value=='KNOWN')
