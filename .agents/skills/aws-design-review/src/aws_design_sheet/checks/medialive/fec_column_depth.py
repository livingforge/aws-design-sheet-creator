"""Checks for AWS::MediaLive::Channel."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'MEDIALIVE_FEC_COLUMN_DEPTH': [CF+'aws-properties-medialive-channel-fecoutputsettings.html'],
}


@resource_check('AWS::MediaLive::Channel')
def evaluate_medialive_fec_column_depth(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::MediaLive::Channel':
        for path in expand(ctx,resource,'/properties/EncoderSettings/OutputGroups/*/Outputs/*/OutputSettings/UdpOutputSettings/FecOutputSettings/ColumnDepth'):
            raw=value(ctx,resource,path)
            emit('MEDIALIVE_FEC_COLUMN_DEPTH',path,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if 4<=raw<=20 else 'FAIL','explicit FEC column depth must be an integer in 4..20; unknown/default values, row-mode conditions and other numeric/PID constraints remain held')
    return results
