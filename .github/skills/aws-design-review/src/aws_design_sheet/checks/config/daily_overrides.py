"""Checks for AWS::Config::ConfigurationRecorder."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand
from ..common.string_lists import strings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CONFIG_DAILY_OVERRIDES': [CF+'aws-properties-config-configurationrecorder-recordingmode.html',CF+'aws-properties-config-configurationrecorder-recordingmodeoverride.html'],
}
DAILY_FORBIDDEN={'AWS::Config::ResourceCompliance','AWS::Config::ConformancePackCompliance','AWS::Config::ConfigurationRecorder'}


@resource_check('AWS::Config::ConfigurationRecorder')
def evaluate_config_daily_overrides(design,resource):
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Config::ConfigurationRecorder':
        for base in expand(ctx,resource,'/properties/RecordingMode/RecordingModeOverrides/*'):
            frequency=value(ctx,resource,base+'/RecordingFrequency')
            if frequency=='CONTINUOUS':continue
            types,pending=strings(ctx,resource,base+'/ResourceTypes')
            verdict='FAIL' if frequency=='DAILY' and set(types)&DAILY_FORBIDDEN else 'NEEDS_REVIEW' if pending or frequency!='DAILY' else 'PASS'
            emit('CONFIG_DAILY_OVERRIDES',base,verdict,'explicit DAILY override cannot include the three Config compliance/recorder types; unknown frequency/types are held')
        frequency=value(ctx,resource,'/properties/RecordingMode/RecordingFrequency')
        if frequency is not ABSENT and frequency!='CONTINUOUS':
            emit('CONFIG_DAILY_OVERRIDES','/properties/RecordingMode/RecordingFrequency','NEEDS_REVIEW','default DAILY effective frequency requires recording-strategy/override analysis; ALL_SUPPORTED automatically keeps the three special types CONTINUOUS, so default DAILY alone is not a failure')
    return results
