import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.imagebuilder.distribution_links import evaluate_imagebuilder_distribution_links
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(container=False,distribution=None,watermarks=None,consumer='ImagePipeline'):
    rec=target('recipe','AWS::ImageBuilder::ContainerRecipe' if container else 'AWS::ImageBuilder::ImageRecipe',Name='recipe',Version='1.0.0',AmiWatermarks=['marker'] if watermarks is None else watermarks)
    dist=target('dist','AWS::ImageBuilder::DistributionConfiguration',Name='dist',Distributions=[distribution if distribution is not None else {'ContainerDistributionConfiguration':{}} if container else {'AmiDistributionConfiguration':{}}])
    main=target('main','AWS::ImageBuilder::'+consumer)
    d=linked_design(dist,[rec,main]);link(d,main,'DistributionConfigurationArn',dist);link(d,main,'ContainerRecipeArn' if container else 'ImageRecipeArn',rec)
    return d,dist,rec,main


def rows(d,r):return {f['rule_id']:f['verdict'] for f in evaluate_imagebuilder_distribution_links(d,r)}


@pytest.mark.parametrize('consumer',['Image','ImagePipeline'])
@pytest.mark.parametrize('container',[False,True])
@pytest.mark.parametrize('match',[False,True])
def test_recipe_type(consumer,container,match):
    distribution={'ContainerDistributionConfiguration':{}} if container==match else {'AmiDistributionConfiguration':{}}
    d,r,*_=fixture(container,distribution,consumer=consumer)
    assert rows(d,r)['IMAGEBUILDER_DISTRIBUTION_RECIPE_TYPE']==('PASS' if match else 'FAIL')


@pytest.mark.parametrize('groups,expected',[(['all'],'FAIL'),(['all',UNKNOWN],'FAIL'),([],'PASS'),([UNKNOWN],'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
@pytest.mark.parametrize('side',['distribution','recipe'])
def test_watermark_public(groups,expected,side):
    d,dist,rec,_=fixture(distribution={'AmiDistributionConfiguration':{'LaunchPermissionConfiguration':{'UserGroups':groups}}})
    assert rows(d,dist if side=='distribution' else rec)['IMAGEBUILDER_WATERMARK_PUBLIC_DISTRIBUTION']==expected


@pytest.mark.parametrize('mode',['unknown_watermarks','inherited_watermarks','external','condition','both_recipes','scope','template','bad_version','bad_arn_name','unknown_distribution'])
def test_uncertainty(mode):
    d,dist,rec,main=fixture()
    if mode in ('unknown_watermarks','inherited_watermarks'):
        next(f for f in rec.fields if f.path=='/properties/AmiWatermarks').candidates[0].value=UNKNOWN if mode=='unknown_watermarks' else []
    if mode=='external':d.relations=[]
    if mode=='condition':d.relations[-1].condition='Maybe'
    if mode=='both_recipes':link(d,main,'ContainerRecipeArn',rec)
    if mode=='scope':rec.scope.region='us-east-1'
    if mode=='template':rec.template=TemplateContext(state='UNRESOLVED')
    if mode in ('bad_version','bad_arn_name'):
        main.fields=target('x',main.type,ImageRecipeArn='arn:aws:imagebuilder:ap-northeast-1:111111111111:image-recipe/'+('wrong' if mode=='bad_arn_name' else 'recipe')+'/'+('2.0.0' if mode=='bad_version' else '1.0.0')).fields
    if mode=='unknown_distribution':next(f for f in dist.fields if f.path=='/properties/Distributions').candidates[0].value=UNKNOWN
    assert rows(d,dist)['IMAGEBUILDER_WATERMARK_PUBLIC_DISTRIBUTION']=='NEEDS_REVIEW'


def test_multiple_consumers_known_conflict_survives_unknown():
    d,dist,rec,main=fixture(distribution={'AmiDistributionConfiguration':{'LaunchPermissionConfiguration':{'UserGroups':['all']}}})
    other=target('other','AWS::ImageBuilder::ImagePipeline');d.resources.append(other);link(d,other,'DistributionConfigurationArn',dist)
    assert rows(d,dist)['IMAGEBUILDER_WATERMARK_PUBLIC_DISTRIBUTION']=='FAIL'
    assert rows(d,dist)['IMAGEBUILDER_DISTRIBUTION_RECIPE_TYPE']=='NEEDS_REVIEW'


def test_matching_literal_recipe_and_distribution_arns():
    d,dist,rec,main=fixture()
    main.fields=target('x',main.type,ImageRecipeArn='arn:aws:imagebuilder:ap-northeast-1:111111111111:image-recipe/recipe/1.0.0',DistributionConfigurationArn='arn:aws:imagebuilder:ap-northeast-1:111111111111:distribution-configuration/dist').fields
    assert rows(d,dist)['IMAGEBUILDER_DISTRIBUTION_RECIPE_TYPE']=='PASS'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    actual=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='IMAGEBUILDER_DISTRIBUTION_RECIPE_TYPE' and f['verdict']=='PASS' for f in actual)
