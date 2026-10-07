"""Checks for AWS::StepFunctions::StateMachineAlias."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'STEPFUNCTIONS_ALIAS_WEIGHT_TOTAL': [CF+'aws-properties-stepfunctions-statemachinealias-routingconfigurationversion.html'],
    'STEPFUNCTIONS_ALIAS_MACHINE_IDENTITY': [CF+'aws-properties-stepfunctions-statemachinealias-routingconfigurationversion.html',CF+'aws-resource-stepfunctions-statemachineversion.html'],
}
MACHINE=r'arn:(?:aws|aws-cn|aws-us-gov):states:[a-z]+(?:-[a-z]+)+-[0-9]+:[0-9]{12}:stateMachine:[A-Za-z0-9_-]+'


def version_machine(ctx,resource,path):
    version=linked(ctx,resource,path,'AWS::StepFunctions::StateMachineVersion') if known_scope(resource) else None
    if version:
        machine=linked(ctx,version,'/properties/StateMachineArn','AWS::StepFunctions::StateMachine')
        if machine:return ('resource',machine.id)
        arn=value(ctx,version,'/properties/StateMachineArn')
        return ('arn',arn) if isinstance(arn,str) and re.fullmatch(MACHINE,arn) else None
    arn=value(ctx,resource,path)
    if isinstance(arn,str) and re.fullmatch(MACHINE+r':[1-9][0-9]*',arn):return ('arn',arn.rsplit(':',1)[0])
    return None


@resource_check('AWS::StepFunctions::StateMachineAlias')
def evaluate_stepfunctions_state_machine_alias(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::StepFunctions::StateMachineAlias':
        path='/properties/RoutingConfiguration';raw=get(path)
        if raw is not ABSENT:
            total=0;pending=not isinstance(raw,list);invalid=False;identities=[];identity_pending=not isinstance(raw,list) or not raw
            for i in range(len(raw)) if isinstance(raw,list) else ():
                p=path+'/'+str(i);weight=get(p+'/Weight')
                if type(weight) is int and 0<=weight<=100:total+=weight
                elif type(weight) is int:invalid=True
                else:pending=True
                ident=version_machine(ctx,resource,p+'/StateMachineVersionArn')
                if ident:identities.append(ident)
                else:identity_pending=True
            invalid|=total>100 or not pending and total!=100
            emit('STEPFUNCTIONS_ALIAS_WEIGHT_TOTAL',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','explicit integer routing weights must sum to 100; known nonnegative subtotal above 100 is invalid even with unknown entries; version existence and duplicate target validity remain separate')
            mismatch=any(len({v for k,v in identities if k==kind})>1 for kind in ('arn','resource'))
            identity_pending|=len({k for k,v in identities})>1
            emit('STEPFUNCTIONS_ALIAS_MACHINE_IDENTITY',path,'FAIL' if mismatch else 'NEEDS_REVIEW' if identity_pending else 'PASS','version ARNs or explicit linked versions must identify one state machine; mixed ARN/resource identities, dynamic/unsupported ARN forms, conditional links and external version existence remain under review')
    return results
