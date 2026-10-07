"""Checks for AWS::IoT::FleetMetric."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

SOURCES = {
    'IOT_FLEET_METRIC_PERIOD': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-fleetmetric.html',
    ],
}


@resource_check('AWS::IoT::FleetMetric')
def evaluate_iot_fleet_metric_period(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    path='/properties/Period';raw=get(path)
    if raw is not ABSENT:
        emit('IOT_FLEET_METRIC_PERIOD',path,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if raw%60==0 else 'FAIL','explicit integer period must be divisible by 60; existing bounds, unknown values and runtime emissions are separate')
    return results
