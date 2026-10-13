"""Whether a resource is resolved from a known template."""


def resolved(resource):
    return resource is not None and (resource.template is None or resource.template.state.value=='KNOWN')
