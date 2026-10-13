"""Checks for AWS::CleanRooms::ConfiguredTable."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLEANROOMS_JOB_ONLY_CONTROLS': [CF+'aws-properties-cleanrooms-configuredtable-analysisrulecustom.html','https://docs.aws.amazon.com/clean-rooms/latest/apireference/API_AnalysisRuleCustom.html'],
}


@resource_check('AWS::CleanRooms::ConfiguredTable')
def evaluate_cleanrooms_job_only_controls(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::CleanRooms::ConfiguredTable':
        for base in expand(ctx,resource,'/properties/AnalysisRules/*/Policy/V1/Custom'):
            analyses=get(base+'/AllowedAnalyses');known=[];pending=not isinstance(analyses,list) or not analyses
            for i in range(len(analyses)) if isinstance(analyses,list) else ():
                item=get(base+'/AllowedAnalyses/'+str(i))
                if item in ('ANY_QUERY','ANY_JOB'):known.append(item)
                else:pending=True
            for key in ('AggregationThresholds','ComparisonControls'):
                path=base+'/'+key;control=get(path)
                if control is ABSENT:continue
                verdict='NEEDS_REVIEW'
                if 'ANY_QUERY' in known:verdict='NOT_APPLICABLE'
                elif not pending and known and all(x=='ANY_JOB' for x in known):
                    verdict='NEEDS_REVIEW' if control is UNKNOWN else 'FAIL'
                emit('CLEANROOMS_JOB_ONLY_CONTROLS',path,verdict,'AggregationThresholds and ComparisonControls are forbidden for an explicitly job-only ANY_JOB list; template ARNs, unknown analyses and unknown control presence remain under review')
    return results
