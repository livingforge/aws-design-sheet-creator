"""Top-level Config frequency applicability without a managed-rule catalog."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'CONFIG_TOP_LEVEL_FREQUENCY_TRIGGER':[CF+'aws-resource-config-configrule.html',CF+'aws-properties-config-configrule-source.html']}
MESSAGES=('ConfigurationItemChangeNotification','OversizedConfigurationItemChangeNotification','ConfigurationSnapshotDeliveryCompleted','ScheduledNotification')


@resource_check('AWS::Config::ConfigRule')
def evaluate_config_frequency(design,resource):
    if resource.type!='AWS::Config::ConfigRule':return []
    ctx=_Context(design,resource);path='/properties/MaximumExecutionFrequency'
    frequency=value(ctx,resource,path);owner=value(ctx,resource,'/properties/Source/Owner');verdict='NEEDS_REVIEW'
    if frequency is ABSENT:verdict='NOT_APPLICABLE'
    elif literal(frequency):
        if owner=='CUSTOM_POLICY':verdict='FAIL'
        elif owner=='CUSTOM_LAMBDA':
            details=value(ctx,resource,'/properties/Source/SourceDetails')
            if isinstance(details,list) and 0<len(details)<=25:
                messages=[value(ctx,resource,'/properties/Source/SourceDetails/'+str(i)+'/MessageType') for i in range(len(details))]
                if 'ConfigurationSnapshotDeliveryCompleted' in messages:verdict='PASS'
                elif all(m in MESSAGES for m in messages):verdict='FAIL'
    f=ctx.finding('CONFIG_TOP_LEVEL_FREQUENCY_TRIGGER',path,verdict,
        'Top-level frequency applies to periodic managed rules or snapshot-triggered custom rules. Custom policy rules only support change notifications. A known Lambda snapshot trigger establishes this condition; managed-rule catalogs and unresolved trigger lists require review. Per-SourceDetail frequency is a separate condition.')
    f['source_checked_at']='2026-10-04';return [f]
