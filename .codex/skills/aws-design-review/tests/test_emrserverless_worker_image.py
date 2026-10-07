import pytest
from aws_design_sheet.checks.emrserverless.worker_image import evaluate_emrserverless_worker_image
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('key',['Driver','Executor','HiveDriver','TezTask','AdditionalWorker'])
@pytest.mark.parametrize('config,want',[({},'FAIL'),({'ImageUri':''},'FAIL'),({'ImageUri':'registry/image:tag'},'PASS'),({'ImageUri':UNKNOWN},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_image_presence(key,config,want):
    r=target('app','AWS::EMRServerless::Application',WorkerTypeSpecifications={key:{'ImageConfiguration':config}})
    assert evaluate_emrserverless_worker_image(linked_design(r),r)[0]['verdict']==want


@pytest.mark.parametrize('raw',[UNKNOWN,[],{'Driver':UNKNOWN},{'Bad/Key':{}},{'Bad~Key':{}}])
def test_unknown_map(raw):
    r=target('app','AWS::EMRServerless::Application',WorkerTypeSpecifications=raw)
    findings=evaluate_emrserverless_worker_image(linked_design(r),r)
    assert findings and all(f['verdict']=='NEEDS_REVIEW' for f in findings)


def test_omitted_configuration_and_independent_workers():
    r=target('app','AWS::EMRServerless::Application',WorkerTypeSpecifications={'Driver':{},'Executor':{'ImageConfiguration':{}}})
    findings=evaluate_emrserverless_worker_image(linked_design(r),r)
    assert len(findings)==1 and findings[0]['path'].endswith('/Executor/ImageConfiguration/ImageUri') and findings[0]['verdict']=='FAIL'


def test_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    r=target('app','AWS::EMRServerless::Application',WorkerTypeSpecifications={'Driver':{'ImageConfiguration':{}}})
    root=Path(__file__).resolve().parents[1]
    findings=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='EMRSERVERLESS_WORKER_IMAGE_URI_REQUIRED' and f['verdict']=='FAIL' for f in findings)
