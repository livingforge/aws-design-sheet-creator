"""Checks for AWS::Glue::Catalog, AWS::Glue::Classifier."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GLUE_CATALOG_ACCOUNT_NAME': [CF+'aws-resource-glue-catalog.html'],
    'GLUE_CSV_DISTINCT_QUOTE': [CF+'aws-properties-glue-classifier-csvclassifier.html'],
}


@resource_check('AWS::Glue::Catalog', 'AWS::Glue::Classifier')
def evaluate_glue_identities(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::Glue::Catalog':
        path='/properties/Name'
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW' if not literal(raw) or not re.fullmatch(r'[0-9]{12}',resource.scope.account) else 'FAIL' if raw==resource.scope.account else 'PASS'
            emit('GLUE_CATALOG_ACCOUNT_NAME',path,verdict,'explicit catalog name must differ from deployment account ID; other naming constraints remain separate')
    if resource.type=='AWS::Glue::Classifier':
        path='/properties/CsvClassifier'
        quote=value(ctx,resource,path+'/QuoteSymbol')
        delimiter=value(ctx,resource,path+'/Delimiter')
        if quote is not ABSENT or delimiter is not ABSENT:
            verdict='NEEDS_REVIEW' if not all(literal(x) and len(x)==1 and x not in '\r\n' for x in (quote,delimiter)) else 'FAIL' if quote==delimiter else 'PASS'
            emit('GLUE_CSV_DISTINCT_QUOTE',path,verdict,'explicit single-character quote and delimiter must differ; omitted defaults and unknown values remain held')
    return results
