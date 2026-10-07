"""Checks for AWS::WorkSpaces::Workspace."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'WORKSPACES_AUTOSTOP_INTERVAL': [CF+'aws-properties-workspaces-workspace-workspaceproperties.html'],
}


@resource_check('AWS::WorkSpaces::Workspace')
def evaluate_workspaces_autostop_interval(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::WorkSpaces::Workspace':
        path='/properties/WorkspaceProperties/RunningModeAutoStopTimeoutInMinutes';raw=get(path)
        if raw is not ABSENT:
            mode=get('/properties/WorkspaceProperties/RunningMode')
            verdict='NEEDS_REVIEW' if mode!='AUTO_STOP' or type(raw) is not int or raw<=0 else 'PASS' if raw%60==0 else 'FAIL'
            emit('WORKSPACES_AUTOSTOP_INTERVAL',path,verdict,'explicit positive integer timeout in AUTO_STOP mode must use 60-minute intervals; nonpositive values, unknown/default modes, other running modes and runtime behavior remain under review')
    return results
