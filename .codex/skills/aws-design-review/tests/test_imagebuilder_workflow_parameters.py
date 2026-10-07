import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.imagebuilder.workflow_parameters import evaluate_imagebuilder_workflow_parameters
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link

DOC='schemaVersion: 1.0\nparameters:\n  - name: required\n    type: string\n  - name: optional\n    type: boolean\n    default: true\n'


def fixture(kind='ImagePipeline'):
    r=target('consumer','AWS::ImageBuilder::'+kind,Workflows=[{'Parameters':[{'Name':'required','Value':['hello']}]}])
    w=target('workflow','AWS::ImageBuilder::Workflow',Data=DOC,Name='workflow',Version='1.0.0',Type='BUILD')
    d=linked_design(r,[w]);link(d,r,'Workflows/0/WorkflowArn',w)
    return d,r,w


@pytest.mark.parametrize('kind',['Image','ImagePipeline'])
@pytest.mark.parametrize('mode,expected',[
    ('required','PASS'),('optional','PASS'),('missing','FAIL'),
    ('unknown_name','FAIL'),('unknown_input','NEEDS_REVIEW'),
    ('duplicate_input','NEEDS_REVIEW'),('no_params','PASS')])
def test_parameter_names_and_defaults(kind,mode,expected):
    d,r,w=fixture(kind);entry=r.fields[0].candidates[0].value[0]
    if mode=='optional':entry['Parameters'].append({'Name':'optional','Value':['false']})
    if mode=='missing':entry.pop('Parameters')
    if mode=='unknown_name':entry['Parameters'].append({'Name':'misspelled','Value':['x']})
    if mode=='unknown_input':entry['Parameters'][0]['Name']=UNKNOWN
    if mode=='duplicate_input':entry['Parameters']*=2
    if mode=='no_params':entry.pop('Parameters');w.fields[0].candidates[0].value='schemaVersion: 1.0\nsteps: []\n'
    assert evaluate_imagebuilder_workflow_parameters(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('doc',[
    'schemaVersion: 2.0\nparameters: []',
    'schemaVersion: 1.0\nparameters: invalid',
    'schemaVersion: 1.0\nparameters: [{name: required}]',
    DOC+'  - name: required\n    type: integer\n',
    'schemaVersion: 1.0\nparameters: &x [*x]',
    'schemaVersion: 1.0\nschemaVersion: 2.0',
    'schemaVersion: 1.0\nparameters: !Custom []',
    'schemaVersion: [',
    '\ud800', 'x'*16001])
def test_unresolved_or_unsupported_documents(doc):
    d,r,w=fixture();w.fields[0].candidates[0].value=doc
    assert evaluate_imagebuilder_workflow_parameters(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('mode',['uri','literal_arn','conditional','template','missing_reference','unknown_parent'])
def test_workflow_selection_is_explicit(mode):
    d,r,w=fixture()
    if mode=='uri':w.fields+=target('dummy',w.type,Uri='s3://bucket/workflow.yml').fields
    if mode=='literal_arn':r.fields[0].candidates[0].value[0]['WorkflowArn']='arn:aws:imagebuilder:ap-northeast-1:111111111111:workflow/build/workflow/1.0.0/1'
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='template':w.template=TemplateContext(state='UNRESOLVED')
    if mode=='missing_reference':d.relations.clear()
    if mode=='unknown_parent':r.fields[0].candidates[0].value=UNKNOWN
    assert evaluate_imagebuilder_workflow_parameters(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='IMAGEBUILDER_WORKFLOW_PARAMETER_NAMES' and f['verdict']=='PASS' for f in results)
