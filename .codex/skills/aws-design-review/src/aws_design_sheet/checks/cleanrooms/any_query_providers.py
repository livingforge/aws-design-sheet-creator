"""Checks for AWS::CleanRooms::ConfiguredTable."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLEANROOMS_ANY_QUERY_PROVIDERS': [CF+'aws-properties-cleanrooms-configuredtable-analysisrulecustom.html'],
}


@resource_check('AWS::CleanRooms::ConfiguredTable')
def evaluate_cleanrooms_any_query_providers(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::CleanRooms::ConfiguredTable':
        for base in expand(ctx,resource,'/properties/AnalysisRules/*/Policy/V1/Custom'):
            raw=get(base+'/AllowedAnalyses');pending=not isinstance(raw,list);any_query=False
            for i in range(len(raw)) if isinstance(raw,list) else ():
                item=get(base+'/AllowedAnalyses/'+str(i))
                if item=='ANY_QUERY':any_query=True
                elif not literal(item):pending=True
            providers=get(base+'/AllowedAnalysisProviders')
            verdict='NEEDS_REVIEW' if pending else 'NOT_APPLICABLE'
            if any_query:verdict='FAIL' if providers is ABSENT else 'PASS' if isinstance(providers,list) else 'NEEDS_REVIEW'
            emit('CLEANROOMS_ANY_QUERY_PROVIDERS',base+'/AllowedAnalysisProviders',verdict,'ANY_QUERY requires AllowedAnalysisProviders presence; documented minimum zero permits an empty list for this presence check; account validity and query permissions are separate')
    return results
