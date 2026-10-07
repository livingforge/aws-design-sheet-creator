"""Checks for AWS::AppMesh::Route."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPMESH_ROUTE_WEIGHT_SUM': [CF+'aws-properties-appmesh-route-weightedtarget.html'],
}


@resource_check('AWS::AppMesh::Route')
def evaluate_appmesh_route_weight_sum(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::AppMesh::Route':
        for kind in ('HttpRoute','Http2Route','GrpcRoute','TcpRoute'):
            path='/properties/Spec/'+kind+'/Action/WeightedTargets';raw=get(path)
            if raw is ABSENT:continue
            pending=not isinstance(raw,list) or not raw;total=0;invalid=False
            for i in range(len(raw)) if isinstance(raw,list) else ():
                weight=get(path+'/'+str(i)+'/Weight')
                if type(weight) is not int:pending=True;continue
                if weight<0 or weight>100:invalid=True
                else:total+=weight
            emit('APPMESH_ROUTE_WEIGHT_SUM',path,'FAIL' if invalid or total>100 else 'NEEDS_REVIEW' if pending else 'PASS','integer target weights must be 0..100 and total at most 100 for each route action; unknown values remain under review unless known weights already exceed the bound; target existence is separate')
    return results
