"""Checks for AWS::Personalize::Solution."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PERSONALIZE_HPO_JOB_CEILINGS': [CF+'aws-properties-personalize-solution-hporesourceconfig.html'],
}


def training_ceiling(ctx,resource,path,maximum):
    if value(ctx,resource,'/properties/PerformHPO') is not True:return 'NEEDS_REVIEW'
    raw=value(ctx,resource,path)
    if not literal(raw) or len(raw)>256 or not re.fullmatch(r'[1-9][0-9]*',raw):return 'NEEDS_REVIEW'
    return 'PASS' if int(raw)<=maximum else 'FAIL'


@resource_check('AWS::Personalize::Solution')
def evaluate_personalize_hpo_job_ceilings(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::Personalize::Solution':
        for key,maximum in [('MaxNumberOfTrainingJobs',40),('MaxParallelTrainingJobs',10)]:
            path='/properties/SolutionConfig/HpoConfig/HpoResourceConfig/'+key
            if value(ctx,resource,path) is not ABSENT:
                emit('PERSONALIZE_HPO_JOB_CEILINGS',path,training_ceiling(ctx,resource,path,maximum),'with HPO explicitly enabled, canonical positive integer strings have total/parallel ceilings 40/10; unknown/default HPO, zero/noncanonical strings, AutoML implications and service training behavior remain held')
    return results
