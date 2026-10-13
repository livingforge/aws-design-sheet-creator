"""DocumentDB event-source type evidence from explicit instance/cluster links."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'DOCDB_EVENT_SOURCE_TYPES':[CF+'aws-resource-docdb-eventsubscription.html',CF+'aws-resource-docdb-dbinstance.html',CF+'aws-resource-docdb-dbcluster.html']}
KINDS={'db-instance':'AWS::DocDB::DBInstance','db-cluster':'AWS::DocDB::DBCluster'}
MODES=set(KINDS)|{'db-parameter-group','db-security-group','db-cluster-snapshot'}


@resource_check('AWS::DocDB::EventSubscription')
def evaluate_docdb_event_sources(design,resource):
    if resource.type!='AWS::DocDB::EventSubscription':return []
    ctx=_Context(design,resource);path='/properties/SourceIds'
    ids=value(ctx,resource,path);mode=value(ctx,resource,'/properties/SourceType');verdict='NEEDS_REVIEW'
    if ids is ABSENT:verdict='NOT_APPLICABLE'
    elif resolved(resource) and isinstance(ids,list) and 0<len(ids)<=1000 and isinstance(mode,str) and mode in MODES:
        kinds=[];pending=False
        for i in range(len(ids)):
            found=[name for name,kind in KINDS.items() if resolved(linked(ctx,resource,path+'/'+str(i),kind))]
            if len(found)==1:kinds.extend(found)
            else:pending=True
        if any(kind!=mode for kind in kinds):verdict='FAIL'
        elif not pending:verdict='PASS'
    return [ctx.finding('DOCDB_EVENT_SOURCE_TYPES',path,verdict,
        'Every explicitly linked DocumentDB instance or cluster must match the documented SourceType. Unknown, conditional or external references remain reviewable. Parameter-group, security-group and snapshot identities are not inferred from unrelated CloudFormation resource types; event delivery and live existence are not checked.')]
