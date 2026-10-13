"""Checks for AWS::Forecast::DatasetGroup."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import expand, literal

SOURCES = {
    'FORECAST_DATASET_DOMAINS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-forecast-datasetgroup.html',
    ],
}


@resource_check('AWS::Forecast::DatasetGroup')
def evaluate_forecast_dataset_domains(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::Forecast::DatasetGroup':
        for p in expand(ctx,resource,'/properties/DatasetArns/*'):
            dataset=linked(ctx,resource,p,'AWS::Forecast::Dataset');domain=get('/properties/Domain');other=value(ctx,dataset,'/properties/Domain') if dataset else None
            emit('FORECAST_DATASET_DOMAINS',p,'NEEDS_REVIEW' if not literal(domain) or not literal(other) else 'PASS' if domain==other else 'FAIL','dataset group and each explicitly linked dataset require matching Domain; unknown, conditional, external and cross-scope references held')
    return results
