"""Checks for AWS::AppStream::ApplicationFleetAssociation, AWS::AppStream::Stack."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPSTREAM_ELASTIC_ASSOCIATION': [CF+'aws-resource-appstream-applicationfleetassociation.html',CF+'aws-resource-appstream-fleet.html'],
    'APPSTREAM_AGENT_VISION': [CF+'aws-properties-appstream-stack-agentaccesssetting.html'],
}


@resource_check('AWS::AppStream::ApplicationFleetAssociation','AWS::AppStream::Stack')
def evaluate_appstream_stack_and_fleet_association(design,resource):
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::AppStream::ApplicationFleetAssociation':
        path='/properties/FleetName'; fleet=linked(ctx,resource,path,'AWS::AppStream::Fleet') if known_scope(resource) else None
        kind=value(ctx,fleet,'/properties/FleetType') if fleet else ABSENT
        verdict='PASS' if kind=='ELASTIC' else 'FAIL' if kind in ('ALWAYS_ON','ON_DEMAND') else 'NEEDS_REVIEW'
        emit('APPSTREAM_ELASTIC_ASSOCIATION',path,verdict,'explicit same-scope fleet relation must target ELASTIC; external, conditional, missing or unknown fleet type remains under review')
    if resource.type=='AWS::AppStream::Stack':
        path='/properties/AgentAccessConfig/Settings'; raw=value(ctx,resource,path)
        if raw is not ABSENT:
            actions={}; pending=not isinstance(raw,list)
            for i in range(len(raw)) if isinstance(raw,list) else ():
                base=path+'/'+str(i); action=value(ctx,resource,base+'/AgentAction'); permission=value(ctx,resource,base+'/Permission')
                if not literal(action) or action not in ('COMPUTER_INPUT','COMPUTER_VISION','FORWARD_MCP_TOOLS') or permission not in ('ENABLED','DISABLED'):pending=True
                elif action in actions:pending=True
                else:actions[action]=permission
            verdict='NEEDS_REVIEW' if pending else 'FAIL' if actions.get('COMPUTER_INPUT')=='ENABLED' and actions.get('COMPUTER_VISION')!='ENABLED' else 'PASS'
            emit('APPSTREAM_AGENT_VISION',path,verdict,'enabled COMPUTER_INPUT requires enabled COMPUTER_VISION; duplicate actions and unresolved settings are held')
    return results
