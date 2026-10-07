"""Checks for AWS::Config::ConfigRule."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CONFIG_RULE_VALUES': [CF+'aws-resource-config-configrule.html', CF+'aws-properties-config-configrule-source.html', CF+'aws-properties-config-configrule-sourcedetail.html', CF+'aws-properties-config-configrule-evaluationmodeconfiguration.html'],
}
FREQUENCIES = ('One_Hour', 'Three_Hours', 'Six_Hours', 'Twelve_Hours', 'TwentyFour_Hours')
CONFIG_ENUMS = (
    ('Source/Owner', ('AWS', 'CUSTOM_LAMBDA', 'CUSTOM_POLICY')),
    ('Source/SourceDetails/*/EventSource', ('aws.config',)),
    ('Source/SourceDetails/*/MessageType', ('ConfigurationItemChangeNotification', 'OversizedConfigurationItemChangeNotification', 'ScheduledNotification', 'ConfigurationSnapshotDeliveryCompleted')),
    ('Source/SourceDetails/*/MaximumExecutionFrequency', FREQUENCIES),
    ('MaximumExecutionFrequency', FREQUENCIES),
    ('EvaluationModes/*/Mode', ('DETECTIVE', 'PROACTIVE')),
)


@resource_check('AWS::Config::ConfigRule')
def evaluate_config_pipeline(design, resource):
    ctx = _Context(design, resource)
    results = []

    def emit(rule, path, verdict, reason):
        f = ctx.finding(rule, path, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)

    def enum(rule, path, allowed):
        raw = value(ctx, resource, path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL', 'checks documented literal enum; conditional applicability, defaults and external service state remain separate')

    if resource.type == 'AWS::Config::ConfigRule':
        for suffix, allowed in CONFIG_ENUMS:
            for path in expand(ctx, resource, '/properties/'+suffix):
                enum('CONFIG_RULE_VALUES', path, allowed)
    return results
