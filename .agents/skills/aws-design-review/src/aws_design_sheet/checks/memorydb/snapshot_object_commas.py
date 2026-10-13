"""Checks for AWS::MemoryDB::Cluster."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'MEMORYDB_SNAPSHOT_OBJECT_COMMAS': [CF+'aws-resource-memorydb-cluster.html'],
}


@resource_check('AWS::MemoryDB::Cluster')
def evaluate_memorydb_snapshot_object_commas(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::MemoryDB::Cluster':
        for path in expand(ctx,resource,'/properties/SnapshotArns/*'):
            raw=get(path);verdict='NEEDS_REVIEW'
            if literal(raw):
                match=re.fullmatch(r'arn:(?:aws|aws-cn|aws-us-gov):s3:::([a-z0-9][a-z0-9.-]*[a-z0-9])/(.+)',raw)
                if match:verdict='FAIL' if ',' in match[2] else 'PASS'
            emit('MEMORYDB_SNAPSHOT_OBJECT_COMMAS',path,verdict,'object key in an explicit ordinary S3 snapshot ARN must contain no literal comma; nonstandard ARN forms, unresolved values and actual object accessibility remain under review')
    return results
