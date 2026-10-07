"""Checks for AWS::Config::DeliveryChannel."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CONFIG_DISTINCT_CHANNEL_LIMIT': [CF+'aws-resource-config-deliverychannel.html'],
}


@resource_check('AWS::Config::DeliveryChannel')
def evaluate_config_distinct_channel_limit(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::Config::DeliveryChannel':
        def name(r):
            if not known_scope(r) or (r.template is not None and r.template.state.value!='KNOWN'):
                return None
            raw = value(ctx,r,'/properties/Name')
            return raw if literal(raw) else None
        own = name(resource)
        duplicate = own is not None and any(other.id!=resource.id and other.type==resource.type and other.scope==resource.scope and name(other) is not None and name(other)!=own for other in design.resources)
        emit('CONFIG_DISTINCT_CHANNEL_LIMIT','/properties/Name','FAIL' if duplicate else 'NEEDS_REVIEW','at most one channel per account/Region; distinct explicit names in the same known design scope prove multiple channels; aliases, missing names, conditional template context, recorder order and deployed inventory remain held')
    return results
