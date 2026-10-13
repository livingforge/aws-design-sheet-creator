"""Checks for AWS::DataBrew::Job."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import expand, known_scope

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DATABREW_RULESET_DATASET': [CF+'aws-properties-databrew-job-validationconfiguration.html',CF+'aws-resource-databrew-ruleset.html'],
}


@resource_check('AWS::DataBrew::Job')
def evaluate_databrew_ruleset_dataset(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::DataBrew::Job':
        dataset=linked(ctx,resource,'/properties/DatasetName','AWS::DataBrew::Dataset') if known_scope(resource) else None
        for path in expand(ctx,resource,'/properties/ValidationConfigurations/*/RulesetArn'):
            ruleset=linked(ctx,resource,path,'AWS::DataBrew::Ruleset') if known_scope(resource) else None
            other=linked(ctx,ruleset,'/properties/TargetArn','AWS::DataBrew::Dataset') if ruleset else None
            verdict='NEEDS_REVIEW'
            if value(ctx,resource,'/properties/Type')=='PROFILE' and dataset and other:verdict='PASS' if dataset.id==other.id else 'FAIL'
            emit('DATABREW_RULESET_DATASET',path,verdict,'explicit profile-job DatasetName and selected ruleset TargetArn links must identify the same dataset; aliases, literals, project inheritance, external or conditional links remain under review')
    return results
