"""Recognize literal-only IoT Events expressions without evaluating code."""
import re
from decimal import Decimal
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'IOTEVENTS_ALARM_LITERAL_VALUES':[CF+'aws-properties-iotevents-alarmmodel-'+part+'.html' for part in ('dynamodb','assetpropertyvalue','assetpropertyvariant')],
 'IOTEVENTS_DETECTOR_LITERAL_VALUES':[CF+'aws-properties-iotevents-detectormodel-'+part+'.html' for part in ('dynamodb','assetpropertyvalue','assetpropertyvariant')],
 'IOTEVENTS_TIMER_LITERAL_DURATION':[CF+'aws-properties-iotevents-detectormodel-settimer.html'],
}
ENUMS={'DynamoDB/HashKeyType':('STRING','NUMBER'),'DynamoDB/RangeKeyType':('STRING','NUMBER'),'DynamoDB/Operation':('INSERT','UPDATE','DELETE'),'IotSiteWise/PropertyValue/Quality':('GOOD','BAD','UNCERTAIN'),'IotSiteWise/PropertyValue/Value/BooleanValue':('TRUE','FALSE')}


def quoted(raw,allowed):
    match=re.fullmatch(r"'([^'\\$\r\n]*)'",raw.strip()) if isinstance(raw,str) and len(raw)<=1024 else None
    if match is None:return 'NEEDS_REVIEW'
    return 'PASS' if match[1] in allowed else 'FAIL'


def duration(raw):
    if not isinstance(raw,str) or len(raw)>64 or not re.fullmatch(r'[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)',raw.strip()):return 'NEEDS_REVIEW'
    n=Decimal(raw.strip())
    if n<1 or n>=31622401:return 'FAIL'
    if 60<=n<=31622400:return 'PASS'
    # Prose gives 1..31622400 but also a minimum of 60 for accuracy;
    # it does not settle the top fractional boundary before/after rounding.
    return 'NEEDS_REVIEW'


@resource_check('AWS::IoTEvents::AlarmModel','AWS::IoTEvents::DetectorModel')
def evaluate_iotevents_literal_expressions(design,resource):
    alarm=resource.type=='AWS::IoTEvents::AlarmModel'
    ctx=_Context(design,resource);known=resource.template is None or resource.template.state.value=='KNOWN'
    patterns=['/properties/AlarmEventActions/AlarmActions/*'] if alarm else ['/properties/DetectorModelDefinition/States/*/'+p+'/Actions/*' for p in ('OnEnter/Events/*','OnExit/Events/*','OnInput/Events/*','OnInput/TransitionEvents/*')]
    rule='IOTEVENTS_ALARM_LITERAL_VALUES' if alarm else 'IOTEVENTS_DETECTOR_LITERAL_VALUES';results=[]
    def emit(rule,path,verdict):
        f=ctx.finding(rule,path,verdict,'Inspect only whole single-quoted enum literals or a plain numeric timer duration; never execute expression text. Concatenations, substitutions, variables, escaped literals and unsupported expression forms remain reviewable. Timer values 1–59 and the upper fractional boundary are held because range/accuracy and rounding wording do not settle them. This does not certify service availability or arbitrary expression results.')
        f['source_checked_at']='2026-10-04';results.append(f)
    for pattern in patterns:
        for base in expand(ctx,resource,pattern):
            if base.count('/')!=pattern.count('/'):
                emit(rule,base,'NEEDS_REVIEW');continue
            for suffix,allowed in ENUMS.items():
                path=base+'/'+suffix;raw=value(ctx,resource,path)
                if raw is not ABSENT:emit(rule,path,quoted(raw,allowed) if known else 'NEEDS_REVIEW')
            if not alarm:
                path=base+'/SetTimer/DurationExpression';raw=value(ctx,resource,path)
                if raw is not ABSENT:emit('IOTEVENTS_TIMER_LITERAL_DURATION',path,duration(raw) if known else 'NEEDS_REVIEW')
    return results
