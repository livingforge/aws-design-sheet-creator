"""Checks for AWS::Timestream::InfluxDBInstance, AWS::Timestream::Table."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'TIMESTREAM_INFLUX_SUBNET_AZ': [CF+'aws-resource-timestream-influxdbinstance.html'],
    'TIMESTREAM_RETENTION_BOUNDS': [CF+'aws-properties-timestream-table-retentionproperties.html','https://docs.aws.amazon.com/timestream/latest/APIReference/API_RetentionProperties.html'],
}


def az_identity(ctx,subnet):
    name=value(ctx,subnet,'/properties/AvailabilityZone');zone=value(ctx,subnet,'/properties/AvailabilityZoneId')
    if zone is ABSENT and isinstance(name,str) and re.fullmatch(re.escape(subnet.scope.region)+r'[a-z]',name):return ('name',name)
    if name is ABSENT and isinstance(zone,str) and re.fullmatch(r'[a-z0-9]+-az[0-9]+',zone):return ('id',zone)
    return None


@resource_check('AWS::Timestream::InfluxDBInstance', 'AWS::Timestream::Table')
def evaluate_timestream_network_shapes(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Timestream::InfluxDBInstance':
        mode=get('/properties/DeploymentType');path='/properties/VpcSubnetIds';raw=get(path)
        if mode!='SINGLE_AZ' and raw is not ABSENT:
            verdict='NEEDS_REVIEW'
            if mode=='WITH_MULTIAZ_STANDBY' and known_scope(resource) and isinstance(raw,list) and len(raw)==2:
                subnets=[linked(ctx,resource,path+'/'+str(i),'AWS::EC2::Subnet') for i in range(2)]
                zones=[az_identity(ctx,s) if s else None for s in subnets]
                if all(zones) and zones[0][0]==zones[1][0]:verdict='PASS' if zones[0]!=zones[1] else 'FAIL'
            emit('TIMESTREAM_INFLUX_SUBNET_AZ',path,verdict,'two explicitly linked Multi-AZ subnets must use different comparable AZ names or IDs; larger lists, mixed name/ID selectors, unknown/conditional/external links and live placement remain under review')
    if resource.type=='AWS::Timestream::Table':
        for key,maximum in [('MemoryStoreRetentionPeriodInHours',8766),('MagneticStoreRetentionPeriodInDays',73000)]:
            path='/properties/RetentionProperties/'+key;raw=get(path)
            if raw is ABSENT:continue
            verdict='NEEDS_REVIEW'
            if isinstance(raw,str) and re.fullmatch(r'0|[1-9][0-9]*',raw):
                bound=str(maximum);too_large=len(raw)>len(bound) or len(raw)==len(bound) and raw>bound
                verdict='FAIL' if raw=='0' or too_large else 'PASS'
            emit('TIMESTREAM_RETENTION_BOUNDS',path,verdict,'canonical decimal string retention must be 1..8766 hours or 1..73000 days per API; other string/numeric forms and omitted values remain under review')
    return results
