"""Checks for AWS::ImageBuilder::InfrastructureConfiguration."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.template_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'IMAGEBUILDER_CONTAINER_METADATA_HOPS': [CF+'aws-properties-imagebuilder-infrastructureconfiguration-instancemetadataoptions.html'],
}


def container_hops(ctx,resource):
    path='/properties/InstanceMetadataOptions'
    hops=value(ctx,resource,path+'/HttpPutResponseHopLimit')
    if not resolved(resource) or value(ctx,resource,path+'/HttpTokens')!='required' or type(hops) is not int or len(ctx.design.resources)>10000:
        return 'NEEDS_REVIEW'
    for consumer in ctx.design.resources:
        if consumer.type not in ('AWS::ImageBuilder::Image','AWS::ImageBuilder::ImagePipeline') or not resolved(consumer):
            continue
        if value(ctx,consumer,'/properties/ImageRecipeArn') is not ABSENT or value(ctx,consumer,'/properties/ImagePipelineExecutionSettings') is not ABSENT:
            continue
        infra=linked(ctx,consumer,'/properties/InfrastructureConfigurationArn',resource.type)
        recipe=linked(ctx,consumer,'/properties/ContainerRecipeArn','AWS::ImageBuilder::ContainerRecipe')
        if infra is not None and infra.id==resource.id and resolved(recipe):
            return 'PASS' if hops>=2 else 'FAIL'
    return 'NEEDS_REVIEW'


@resource_check('AWS::ImageBuilder::InfrastructureConfiguration')
def evaluate_imagebuilder_container_metadata_hops(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::ImageBuilder::InfrastructureConfiguration':
        path='/properties/InstanceMetadataOptions'
        if value(ctx,resource,path) is not ABSENT:
            emit('IMAGEBUILDER_CONTAINER_METADATA_HOPS',path,container_hops(ctx,resource),'explicit required HTTP tokens and uniquely linked container recipe consumer require at least two metadata response hops; unknown/default settings, ambiguous consumers and external usage remain held')
    return results
