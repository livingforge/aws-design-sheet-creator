"""Explicit local recorder creation ordering for Config delivery channels."""
from ...template_dependencies import members, ordering
from ..registry import resource_check
from ..common.context_values import _Context
from ..common.scoped_resolution import resolved

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {'CONFIG_CHANNEL_RECORDER_ORDER': [CF+'aws-resource-config-deliverychannel.html',
    CF+'aws-resource-config-configurationrecorder.html',CF+'aws-attribute-dependson.html']}


@resource_check('AWS::Config::DeliveryChannel')
def evaluate_config_recorder_order(design, resource):
    if resource.type != 'AWS::Config::DeliveryChannel':
        return []
    ctx = _Context(design, resource)
    recorders = [r for r in members(design,resource) if r.type == 'AWS::Config::ConfigurationRecorder']
    verdict = 'NEEDS_REVIEW'
    if resolved(resource) and len(recorders) == 1 and resolved(recorders[0]):
        try:
            verdict = ordering(ctx,'CONFIG_CHANNEL_RECORDER_ORDER',recorders)['verdict']
        except RecursionError:
            pass
    f = ctx.finding('CONFIG_CHANNEL_RECORDER_ORDER','/template/depends_on',verdict,
        'The unique explicitly co-declared configuration recorder must precede delivery channel creation. Known direct or transitive dependencies establish local order; unknown lists, absent/external/multiple recorders and template membership remain reviewable. Does not certify runtime recorder state or channel uniqueness.')
    f['source_checked_at'] = '2026-10-04'
    return [f]
