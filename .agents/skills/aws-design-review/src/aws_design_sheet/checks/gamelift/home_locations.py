"""Checks for AWS::GameLift::ContainerFleet, AWS::GameLift::Fleet."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GAMELIFT_CONTAINER_HOME_LOCATION': [CF+'aws-resource-gamelift-containerfleet.html'],
    'GAMELIFT_EC2_HOME_LOCATION': [CF+'aws-resource-gamelift-fleet.html'],
}


@resource_check('AWS::GameLift::ContainerFleet', 'AWS::GameLift::Fleet')
def evaluate_gamelift_home_locations(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type in ('AWS::GameLift::ContainerFleet','AWS::GameLift::Fleet'):
        path='/properties/Locations'
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            container=resource.type.endswith('ContainerFleet')
            applicable=container or value(ctx,resource,'/properties/ComputeType')=='EC2'
            verdict='NEEDS_REVIEW'
            if applicable and known_scope(resource) and isinstance(raw,list) and len(raw)<=100:
                locations=[value(ctx,resource,path+'/'+str(i)+'/Location') for i in range(len(raw))]
                verdict='PASS' if resource.scope.region in locations else 'FAIL' if all(literal(x) for x in locations) else 'NEEDS_REVIEW'
            emit('GAMELIFT_CONTAINER_HOME_LOCATION' if container else 'GAMELIFT_EC2_HOME_LOCATION',path,verdict,'explicit locations must include deployment home Region; ordinary Fleet check requires explicit EC2; omitted/default/ANYWHERE contexts, unknown members and regional availability remain held')
    return results
