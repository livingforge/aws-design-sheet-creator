"""Checks for AWS::DocDB::EventSubscription."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.string_lists import strings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DOCDB_SOURCE_ID_HYPHENS': [CF+'aws-resource-docdb-eventsubscription.html'],
}


@resource_check('AWS::DocDB::EventSubscription')
def evaluate_docdb_source_id_hyphens(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::DocDB::EventSubscription':
        path='/properties/SourceIds'
        if value(ctx,resource,path) is not ABSENT:
            names,pending=strings(ctx,resource,path)
            invalid=any(n.endswith('-') or '--' in n for n in names)
            emit('DOCDB_SOURCE_ID_HYPHENS',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','literal SourceIds cannot end with a hyphen or contain consecutive hyphens; existing character checks and actual source existence remain separate')
    return results
