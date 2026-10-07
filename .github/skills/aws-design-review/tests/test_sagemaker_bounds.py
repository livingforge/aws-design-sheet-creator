import pytest
from aws_design_sheet.checks.sagemaker.bounds import evaluate_sagemaker_bounds
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def fixture(**props):
    r=target('config','AWS::SageMaker::EndpointConfig',**props)
    return linked_design(r),r


def result(d,r,path):return next(f['verdict'] for f in evaluate_sagemaker_bounds(d,r) if f['path']=='/properties/'+path)


@pytest.mark.parametrize('field,count,want',[
    ('ProductionVariants',0,'FAIL'),('ProductionVariants',1,'PASS'),('ProductionVariants',10,'PASS'),('ProductionVariants',11,'FAIL'),
    ('ShadowProductionVariants',0,'FAIL'),('ShadowProductionVariants',11,'FAIL'),
    ('Tags',0,'PASS'),('Tags',50,'PASS'),('Tags',51,'FAIL')])
def test_root_array_bounds(field,count,want):
    d,r=fixture(**{field:[{}]*count});assert result(d,r,field)==want


@pytest.mark.parametrize('path,count,want',[
    ('SecurityGroupIds',0,'FAIL'),('SecurityGroupIds',5,'PASS'),('SecurityGroupIds',6,'FAIL'),
    ('Subnets',1,'PASS'),('Subnets',16,'PASS'),('Subnets',17,'FAIL')])
def test_vpc_array_bounds(path,count,want):
    d,r=fixture(VpcConfig={path:['id']*count});assert result(d,r,'VpcConfig/'+path)==want


@pytest.mark.parametrize('field,number,want',[
    ('MaxConcurrency',0,'FAIL'),('MaxConcurrency',1,'PASS'),('MaxConcurrency',200,'PASS'),('MaxConcurrency',201,'FAIL'),
    ('ProvisionedConcurrency',0,'FAIL'),('ProvisionedConcurrency',200,'PASS'),('ProvisionedConcurrency',201,'FAIL'),
    ('MemorySizeInMB',1023,'FAIL'),('MemorySizeInMB',1024,'PASS'),('MemorySizeInMB',6144,'PASS'),('MemorySizeInMB',6145,'FAIL'),
    ('MaxConcurrency',True,'NEEDS_REVIEW'),('MaxConcurrency','20','NEEDS_REVIEW'),('MemorySizeInMB',UNKNOWN,'NEEDS_REVIEW')])
def test_serverless_boundaries(field,number,want):
    d,r=fixture(ProductionVariants=[{'ServerlessConfig':{field:number}}]);assert result(d,r,'ProductionVariants/0/ServerlessConfig/'+field)==want


def test_all_variants_and_shadow_checked():
    d,r=fixture(ProductionVariants=[{}, {'InstancePools':[{}]*6}],ShadowProductionVariants=[{'ServerlessConfig':{'MaxConcurrency':201}}])
    assert result(d,r,'ProductionVariants/1/InstancePools')=='FAIL'
    assert result(d,r,'ShadowProductionVariants/0/ServerlessConfig/MaxConcurrency')=='FAIL'


@pytest.mark.parametrize('count,want',[(0,'FAIL'),(32,'PASS'),(33,'FAIL')])
def test_capture_options(count,want):
    d,r=fixture(DataCaptureConfig={'CaptureOptions':[{}]*count});assert result(d,r,'DataCaptureConfig/CaptureOptions')==want


def test_unknown_parent_never_measures_as_known_array():
    d,r=fixture(ProductionVariants=UNKNOWN)
    assert all(f['verdict']=='NEEDS_REVIEW' for f in evaluate_sagemaker_bounds(d,r))


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r=fixture(ProductionVariants=[{}]);root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="SAGEMAKER_ENDPOINT_ARRAY_BOUNDS" and f["verdict"]=="PASS" for f in results)
