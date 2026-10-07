"""Checks for AWS::BedrockAgentCore::GatewayRule."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand
from ..common.numbers import number

AGENT='https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/'
CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'AGENTCORE_GATEWAY_TRAFFIC_TOTAL': [CF+'aws-properties-bedrockagentcore-gatewayrule-'+s+'.html' for s in ('weightedoverride','weightedroute','trafficsplitentry','targettrafficsplitentry')]+[AGENT+'API_TrafficSplitEntry.html',AGENT+'API_TargetTrafficSplitEntry.html'],
}


def traffic_split(ctx,resource,path,override):
    raw=value(ctx,resource,path)
    if not isinstance(raw,list):return 'NEEDS_REVIEW'
    if len(raw)!=2:return 'FAIL'
    total=0;pending=not override
    for i in range(len(raw)):
        weight=number(value(ctx,resource,path+'/'+str(i)+'/Weight'))
        if weight is None:pending=True;continue
        if weight<1 or weight>99:return 'FAIL'
        # CFN says Number, control-plane API says Integer: fractional values held.
        if weight!=weight.to_integral_value():pending=True
        total+=weight
    if pending:return 'NEEDS_REVIEW'
    return 'PASS' if total==100 else 'FAIL'


@resource_check('AWS::BedrockAgentCore::GatewayRule')
def evaluate_bedrockagentcore_gateway_traffic_total(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::BedrockAgentCore::GatewayRule':
        for sub,override in (('ConfigurationBundle/WeightedOverride',True),('RouteToTarget/WeightedRoute',False)):
            for path in expand(ctx,resource,'/properties/Actions/*/'+sub+'/TrafficSplit'):
                emit('AGENTCORE_GATEWAY_TRAFFIC_TOTAL',path,traffic_split(ctx,resource,path,override),'two weights in 1..99; integer-valued WeightedOverride weights must sum to 100; fractional values conflict with API Integer and WeightedRoute sum lacks explicit source, so both remain under review')
    return results
