"""Checks for AWS::IoT::JobTemplate, AWS::IoT::TopicRule."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.decimal_places import decimal_places
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

API='https://docs.aws.amazon.com/iot/latest/apireference/'
SOURCES = {
    'IOT_JOB_TEMPLATE_DECIMALS': [API+'API_AbortCriteria.html',API+'API_ExponentialRolloutRate.html'],
    'IOT_TOPIC_ACTION_LITERAL_VALUES': [API+'API_AssetPropertyValue.html',API+'API_MqttHeaders.html',API+'API_CloudwatchAlarmAction.html'],
}


@resource_check('AWS::IoT::JobTemplate', 'AWS::IoT::TopicRule')
def evaluate_iot_unit_and_action_values(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    def enum(rule,path,allowed):
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            emit(rule,path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','explicit case-sensitive API values only; substitutions, unknown input and omitted defaults remain held')
    if resource.type=='AWS::IoT::JobTemplate':
        paths=[(p,2) for p in expand(ctx,resource,'/properties/AbortConfig/CriteriaList/*/ThresholdPercentage')]
        path='/properties/JobExecutionsRolloutConfig/ExponentialRate/IncrementFactor'
        if value(ctx,resource,path) is not ABSENT:paths.append((path,1))
        for path,places in paths:
            emit('IOT_JOB_TEMPLATE_DECIMALS',path,decimal_places(value(ctx,resource,path),places),'serialized finite numeric value supports at most '+str(places)+' decimal places; unknown/non-numeric input and value ranges remain separate')
    if resource.type=='AWS::IoT::TopicRule':
        seen=set()
        for base in ('/properties/TopicRulePayload/Actions/*','/properties/TopicRulePayload/ErrorAction'):
            for suffix,allowed in (
                ('/IotSiteWise/PutAssetPropertyValueEntries/*/PropertyValues/*/Quality',('GOOD','BAD','UNCERTAIN')),
                ('/Republish/Headers/PayloadFormatIndicator',('UNSPECIFIED_BYTES','UTF8_DATA')),
                ('/CloudwatchAlarm/StateValue',('OK','ALARM','INSUFFICIENT_DATA')),
            ):
                for path in expand(ctx,resource,base+suffix):
                    if path not in seen:
                        seen.add(path)
                        enum('IOT_TOPIC_ACTION_LITERAL_VALUES',path,allowed)
    return results
