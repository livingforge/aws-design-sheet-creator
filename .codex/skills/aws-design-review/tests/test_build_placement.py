from pathlib import Path
import pytest
from aws_design_sheet.checks.imagebuilder.container_metadata_hops import evaluate_imagebuilder_container_metadata_hops
from aws_design_sheet.checks.gameliftstreams.stream_source_region import evaluate_gameliftstreams_stream_source_region
from aws_design_sheet.checks.registry import combine
build_placement_checks = combine(evaluate_imagebuilder_container_metadata_hops, evaluate_gameliftstreams_stream_source_region)
from aws_design_sheet.models import Relation, TemplateContext
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('kind',['Image','ImagePipeline'])
@pytest.mark.parametrize('mode',['one','two','optional','unknown_hops','missing_hops','boolean','no_consumer','no_recipe','conditional','scope','template','recipe_template','image_recipe','pipeline_settings'])
def test_hops(kind,mode):
    options={'HttpTokens':'optional' if mode=='optional' else 'required','HttpPutResponseHopLimit':UNKNOWN if mode=='unknown_hops' else True if mode=='boolean' else 2 if mode=='two' else 1}
    if mode=='missing_hops':options.pop('HttpPutResponseHopLimit')
    r=target('main','AWS::ImageBuilder::InfrastructureConfiguration',InstanceMetadataOptions=options)
    consumer=target('consumer','AWS::ImageBuilder::'+kind,InfrastructureConfigurationArn='infra',ContainerRecipeArn='recipe',**({'ImageRecipeArn':'ami-recipe'} if mode=='image_recipe' else {'ImagePipelineExecutionSettings':{'ImagePipelineArn':'pipeline'}} if mode=='pipeline_settings' else {}))
    recipe=target('recipe','AWS::ImageBuilder::ContainerRecipe')
    d=linked_design(r,[] if mode=='no_consumer' else [consumer,recipe])
    for path,target_id in [('InfrastructureConfigurationArn','main'),('ContainerRecipeArn','recipe')]:
        if mode=='no_recipe' and target_id=='recipe':continue
        d.relations.append(Relation(id=path,source_resource_id='consumer',source_path='/properties/'+path,target_resource_id=target_id,evidence_ids=[],condition='Maybe' if mode=='conditional' else None))
    if mode=='scope':consumer.scope.region='us-east-1'
    if mode=='template':consumer.template=TemplateContext(state='UNRESOLVED')
    if mode=='recipe_template':recipe.template=TemplateContext(state='UNRESOLVED')
    assert build_placement_checks(d,r)[0]['verdict']==('FAIL' if mode=='one' else 'PASS' if mode=='two' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['same','region','account','environment','name','unknown','conditional','ambiguous','missing','wrong_type','template','bucket_template','scope','https','query','fragment','root','prefix'])
def test_source(mode):
    uri=UNKNOWN if mode=='unknown' else 'https://my-bucket/key' if mode=='https' else 's3://my-bucket?version=1' if mode=='query' else 's3://my-bucket/key#fragment' if mode=='fragment' else 's3://my-bucket' if mode=='root' else 's3://my-bucket/a/b/' if mode=='prefix' else 's3://my-bucket/content/'
    r=target('main','AWS::GameLiftStreams::Application',ApplicationSourceUri=uri)
    b=target('bucket','AWS::S3::Bucket',BucketName='other-name' if mode=='name' else 'my-bucket')
    d=linked_design(r,[b],[] if mode=='missing' else [('ApplicationSourceUri','bucket')])
    if mode in ('region','account','environment'):setattr(b.scope,mode,{'region':'us-east-1','account':'222222222222','environment':'other'}[mode])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='wrong_type':b.type='AWS::SNS::Topic'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='bucket_template':b.template=TemplateContext(state='UNRESOLVED')
    if mode=='scope':b.scope.account='unknown'
    assert build_placement_checks(d,r)[0]['verdict']==('PASS' if mode in ('same','account','root','prefix') else 'FAIL' if mode=='region' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::ImageBuilder::InfrastructureConfiguration','AWS::GameLiftStreams::Application'])
def test_omitted(kind):
    r=target('main',kind)
    assert not build_placement_checks(linked_design(r),r)


def test_checker_source():
    r=target('main','AWS::GameLiftStreams::Application',ApplicationSourceUri='s3://my-bucket/content/')
    b=target('bucket','AWS::S3::Bucket',BucketName='my-bucket');b.scope.region='us-east-1'
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r,[b],[('ApplicationSourceUri','bucket')]))['results']
    assert any(f['rule_id']=='GAMELIFT_STREAM_SOURCE_REGION' and f['verdict']=='FAIL' for f in results)
