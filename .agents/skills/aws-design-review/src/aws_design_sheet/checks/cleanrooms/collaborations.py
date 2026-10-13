"""Checks for these resource types:

- AWS::CleanRooms::Collaboration
- AWS::CleanRooms::IntermediateTable
- AWS::CleanRooms::Membership
"""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLEANROOMS_JOB_PAYER_ABILITIES': [CF+'aws-properties-cleanrooms-collaboration-jobcomputepaymentconfig.html'],
    'CLEANROOMS_INTERMEDIATE_JOB_ONLY': [CF+'aws-properties-cleanrooms-intermediatetable-intermediatetableanalysisrulecustom.html','https://docs.aws.amazon.com/clean-rooms/latest/apireference/API_IntermediateTableAnalysisRuleCustom.html'],
    'CLEANROOMS_CREATOR_JOB_PAYMENT': [CF+'aws-properties-cleanrooms-membership-membershipjobcomputepaymentconfig.html'],
    'CLEANROOMS_SINGLE_FILE_ENGINE': [CF+'aws-properties-cleanrooms-membership-protectedquerys3outputconfiguration.html'],
}


@resource_check(
    'AWS::CleanRooms::Collaboration',
    'AWS::CleanRooms::IntermediateTable',
    'AWS::CleanRooms::Membership',
)
def evaluate_cleanrooms_collaborations(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):
        result=ctx.finding(rule,p,v,reason);result['source_checked_at']='2026-10-04';results.append(result)
    def enum(rule,p,allowed):
        raw=get(p)
        if raw is not ABSENT:emit(rule,p,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','literal value checked against current explicit CF allowed values; no omitted values inferred')
    if resource.type=='AWS::CleanRooms::Collaboration':
        pairs=[('/properties/CreatorMemberAbilities','/properties/CreatorPaymentConfiguration/JobCompute/IsResponsible')]
        pairs.extend((p+'/MemberAbilities',p+'/PaymentConfiguration/JobCompute/IsResponsible') for p in expand(ctx,resource,'/properties/Members/*'))
        for abilities_path,p in pairs:
            raw=get(p)
            if raw is ABSENT:continue
            abilities=get(abilities_path);v='NEEDS_REVIEW'
            if isinstance(abilities,list):
                values=[get(abilities_path+'/'+str(i)) for i in range(len(abilities))]
                if 'CAN_QUERY' in values and 'CAN_RUN_JOB' in values and type(raw) is bool:v='PASS' if raw else 'FAIL'
            emit('CLEANROOMS_JOB_PAYER_ABILITIES',p,v,'checks documented payer condition for a member explicitly able to run both queries and jobs; single-ability, omitted and unknown cases held')
    if resource.type=='AWS::CleanRooms::IntermediateTable':
        for base in expand(ctx,resource,'/properties/AnalysisRules/*/Policy/V1/Custom'):
            analyses=get(base+'/AllowedAnalyses')
            values=[get(base+'/AllowedAnalyses/'+str(i)) for i in range(len(analyses))] if isinstance(analyses,list) else []
            only_jobs=bool(values) and all(x=='ANY_JOB' for x in values)
            for key in ('AggregationThresholds','ComparisonControls'):
                p=base+'/'+key;raw=get(p)
                if raw is ABSENT:continue
                emit('CLEANROOMS_INTERMEDIATE_JOB_ONLY',p,'FAIL' if only_jobs and isinstance(raw,(dict,list)) else 'NEEDS_REVIEW','explicit nonempty ANY_JOB-only analysis list cannot use aggregation/comparison controls; templates, mixed/unknown modes and unresolved controls held')
    if resource.type=='AWS::CleanRooms::Membership':
        collab=linked(ctx,resource,'/properties/CollaborationIdentifier','AWS::CleanRooms::Collaboration')
        p='/properties/PaymentConfiguration/JobCompute/IsResponsible';raw=get(p)
        if raw is not ABSENT:
            expected=value(ctx,collab,'/properties/CreatorPaymentConfiguration/JobCompute/IsResponsible') if collab and re.fullmatch('[0-9]{12}',resource.scope.account) else None
            emit('CLEANROOMS_CREATOR_JOB_PAYMENT',p,'NEEDS_REVIEW' if type(raw) is not bool or type(expected) is not bool else 'PASS' if raw==expected else 'FAIL','compares creator membership JobCompute acceptance to same-scope linked collaboration creator configuration; cross-account members and other payment categories remain held')
        p='/properties/DefaultResultConfiguration/OutputConfiguration/S3/SingleFileOutput';raw=get(p)
        if raw is not ABSENT:
            engine=value(ctx,collab,'/properties/AnalyticsEngine') if collab else None
            v='PASS' if engine=='SPARK' and type(raw) is bool else 'FAIL' if engine=='CLEAN_ROOMS_SQL' and type(raw) is bool else 'NEEDS_REVIEW'
            emit('CLEANROOMS_SINGLE_FILE_ENGINE',p,v,'SingleFileOutput parameter, including explicit false, is supported only by a linked SPARK collaboration; unknown/default engine or external links held')
    return results
