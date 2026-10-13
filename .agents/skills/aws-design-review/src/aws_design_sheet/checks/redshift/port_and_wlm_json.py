"""Checks for AWS::Redshift::Cluster, AWS::Redshift::ClusterParameterGroup."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.json_verdict import json_verdict
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'REDSHIFT_NODE_PORT_RANGE': [CF+'aws-resource-redshift-cluster.html'],
    'REDSHIFT_WLM_JSON_SYNTAX': [CF+'aws-resource-redshift-clusterparametergroup.html'],
}


def port_verdict(ctx,r):
    port=value(ctx,r,'/properties/Port');node=value(ctx,r,'/properties/NodeType')
    if type(port) is not int or not literal(node):return 'NEEDS_REVIEW'
    if node in ('dc2.large','dc2.8xlarge'):return 'PASS' if 1150<=port<=65535 else 'FAIL'
    if node in ('rg.xlarge','rg.4xlarge','ra3.large','ra3.xlplus','ra3.4xlarge','ra3.16xlarge'):
        # Existing RG/RA3 clusters need not change older ports: lifecycle is unknown.
        return 'PASS' if 5431<=port<=5455 or 8191<=port<=8215 else 'NEEDS_REVIEW'
    return 'NEEDS_REVIEW'


@resource_check('AWS::Redshift::Cluster', 'AWS::Redshift::ClusterParameterGroup')
def evaluate_redshift_port_and_wlm_json(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Redshift::Cluster' and value(ctx,resource,'/properties/Port') is not ABSENT:
        emit('REDSHIFT_NODE_PORT_RANGE','/properties/Port',port_verdict(ctx,resource),'explicit documented node and integer port range; grandfathered RG/RA3 out-of-range ports, unknown node, omitted defaults and lifecycle remain held')
    if resource.type=='AWS::Redshift::ClusterParameterGroup':
        for path in expand(ctx,resource,'/properties/Parameters/*'):
            name=value(ctx,resource,path+'/ParameterName')
            if name=='wlm_json_configuration':
                emit('REDSHIFT_WLM_JSON_SYNTAX',path+'/ParameterValue',json_verdict(value(ctx,resource,path+'/ParameterValue')),'bounded JSON syntax only; complete WLM key/value schema, runtime compatibility and unknown/dynamic values remain held')
            elif not literal(name):
                emit('REDSHIFT_WLM_JSON_SYNTAX',path,'NEEDS_REVIEW','parameter name or collection unresolved; WLM applicability cannot be established')
    return results
