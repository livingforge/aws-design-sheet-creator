"""Checks for these resource types:

- AWS::ImageBuilder::Component
- AWS::ImageBuilder::ContainerRecipe
- AWS::ImageBuilder::ImageRecipe
- AWS::ImageBuilder::InfrastructureConfiguration
- AWS::ImageBuilder::Workflow
"""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

VERSIONS={kind:'IMAGEBUILDER_'+label+'_VERSION_NODES' for kind,label in (
    ('Component','COMPONENT'),('ContainerRecipe','CONTAINER_RECIPE'),('ImageRecipe','IMAGE_RECIPE'),('Workflow','WORKFLOW'))}
SOURCES = {
    'IMAGEBUILDER_COMPONENT_VERSION_NODES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-imagebuilder-component.html',
    ],
    'IMAGEBUILDER_CONTAINER_RECIPE_VERSION_NODES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-imagebuilder-containerrecipe.html',
    ],
    'IMAGEBUILDER_IMAGE_RECIPE_VERSION_NODES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-imagebuilder-imagerecipe.html',
    ],
    'IMAGEBUILDER_WORKFLOW_VERSION_NODES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-imagebuilder-workflow.html',
    ],
    'IMAGEBUILDER_RESOURCE_TAG_PREFIX': [
        'https://docs.aws.amazon.com/imagebuilder/latest/APIReference/API_CreateInfrastructureConfiguration.html',
    ],
}


@resource_check(*('AWS::ImageBuilder::'+kind for kind in VERSIONS),'AWS::ImageBuilder::InfrastructureConfiguration')
def evaluate_imagebuilder_tag_prefix(design,resource):
    ctx=_Context(design,resource);results=[];kind=resource.type.split('::')[-1]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if kind in VERSIONS:
        path='/properties/Version';raw=get(path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW'
            if isinstance(raw,str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',raw):
                # Compare decimal strings without Python's integer conversion size limit.
                nodes=[x.lstrip('0') or '0' for x in raw.split('.')]
                verdict='FAIL' if any(len(x)>10 or len(x)==10 and x>'1073741823' for x in nodes) else 'PASS'
            emit(VERSIONS[kind],path,verdict,'each of three explicit decimal version nodes must be at most 1073741823; wildcard versions, unknown values and other syntax remain under review; build versions and external uniqueness are separate')
    if resource.type=='AWS::ImageBuilder::InfrastructureConfiguration':
        path='/properties/ResourceTags';raw=get(path)
        if raw is not ABSENT:
            pending=not isinstance(raw,dict);invalid=False
            for key in raw if isinstance(raw,dict) else ():
                if not literal(key):pending=True
                elif key.startswith('aws:'):invalid=True
                elif key.lower().startswith('aws:'):pending=True
            emit('IMAGEBUILDER_RESOURCE_TAG_PREFIX',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','resource tag keys cannot start with literal lowercase aws:; case variants and unresolved keys remain under review; existing reserved-name checks stay separate')
    return results
