"""Checks for AWS::DocDB::DBCluster, AWS::DocDB::DBInstance."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.maintenance_windows import window

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DOCDB_CLUSTER_WINDOWS': [CF+'aws-resource-docdb-dbcluster.html'],
    'DOCDB_INSTANCE_WINDOW': [CF+'aws-resource-docdb-dbinstance.html'],
}


@resource_check('AWS::DocDB::DBCluster','AWS::DocDB::DBInstance')
def evaluate_docdb_windows(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    windows={
        'AWS::DocDB::DBCluster':('DOCDB_CLUSTER_WINDOWS','/properties/PreferredMaintenanceWindow'),
        'AWS::DocDB::DBInstance':('DOCDB_INSTANCE_WINDOW','/properties/PreferredMaintenanceWindow'),
    }
    if resource.type in windows:
        rule,path=windows[resource.type];raw=value(ctx,resource,path);maintenance=window(raw,True)
        if raw is not ABSENT:
            emit(rule,path,'NEEDS_REVIEW' if maintenance is None else 'PASS' if maintenance[1]-maintenance[0]>=30 else 'FAIL','explicit UTC weekly window must span at least 30 minutes; wraparound is counted; equal endpoints, unknown and unsupported formats remain under review')
        if resource.type=='AWS::DocDB::DBCluster':
            backup_path='/properties/PreferredBackupWindow';raw_backup=value(ctx,resource,backup_path);backup=window(raw_backup)
            if raw_backup is not ABSENT:
                emit(rule,backup_path,'NEEDS_REVIEW' if backup is None else 'PASS' if backup[1]-backup[0]>=30 else 'FAIL','explicit daily UTC backup window must span at least 30 minutes; equal endpoints and unknown formats remain under review')
            if raw_backup is not ABSENT or raw is not ABSENT:
                verdict='NEEDS_REVIEW'
                if backup and maintenance:
                    overlap=any(max(maintenance[0],backup[0]+day*1440)<min(maintenance[1],backup[1]+day*1440) for day in range(-1,15))
                    verdict='FAIL' if overlap else 'PASS'
                emit(rule,'/properties',verdict,'daily backup and weekly maintenance windows must not overlap; touching endpoints do not overlap; omitted service-selected windows remain unverified')
    return results
