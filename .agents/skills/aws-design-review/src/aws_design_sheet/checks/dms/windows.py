"""Checks for AWS::DMS::ReplicationConfig, AWS::DMS::ReplicationInstance."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.maintenance_windows import window

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DMS_CONFIG_WINDOW': [CF+'aws-properties-dms-replicationconfig-computeconfig.html'],
    'DMS_INSTANCE_WINDOW': [CF+'aws-resource-dms-replicationinstance.html'],
}


@resource_check('AWS::DMS::ReplicationConfig','AWS::DMS::ReplicationInstance')
def evaluate_dms_windows(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    windows={
        'AWS::DMS::ReplicationConfig':('DMS_CONFIG_WINDOW','/properties/ComputeConfig/PreferredMaintenanceWindow'),
        'AWS::DMS::ReplicationInstance':('DMS_INSTANCE_WINDOW','/properties/PreferredMaintenanceWindow'),
    }
    if resource.type in windows:
        rule,path=windows[resource.type];raw=value(ctx,resource,path);maintenance=window(raw,True)
        if raw is not ABSENT:
            emit(rule,path,'NEEDS_REVIEW' if maintenance is None else 'PASS' if maintenance[1]-maintenance[0]>=30 else 'FAIL','explicit UTC weekly window must span at least 30 minutes; wraparound is counted; equal endpoints, unknown and unsupported formats remain under review')
    return results
