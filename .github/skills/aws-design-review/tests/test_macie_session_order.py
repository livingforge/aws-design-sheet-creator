from pathlib import Path
import pytest
from aws_design_sheet.checker import Checker
from aws_design_sheet.checks.macie.session_order import evaluate_macie_session_order, TYPES
from test_autoscaling_group_and_scaling_policy import target, linked_design
from test_template_dependencies import template, link


def setup(kind, deps=('session',)):
    main=template(target('main',kind),deps)
    session=template(target('session','AWS::Macie::Session'))
    return linked_design(main,[session]),main,session


@pytest.mark.parametrize('kind',TYPES)
@pytest.mark.parametrize('deps,expected',[(('session',),'PASS'),((),'FAIL'),(None,'NEEDS_REVIEW'),(('external',),'NEEDS_REVIEW')])
def test_order(kind,deps,expected):
    data,main,_=setup(kind,deps)
    assert evaluate_macie_session_order(data,main)[0]['verdict']==expected


@pytest.mark.parametrize('kind',TYPES)
@pytest.mark.parametrize('mode',['direct','transitive','implicit'])
def test_known_paths(kind,mode):
    data,main,session=setup(kind)
    if mode!='direct':
        middle=template(target('middle','AWS::S3::Bucket'),['session'])
        data.resources.append(middle)
        main.template.depends_on=['middle'] if mode=='transitive' else []
        if mode=='implicit':link(data,main,'Description',middle)
    row=evaluate_macie_session_order(data,main)[0]
    assert row['verdict']=='PASS'
    assert row['evidence_ids']


@pytest.mark.parametrize('mode',['no_template','other_stack','other_scope','unknown_session','duplicate','missing','conditional'])
def test_ambiguity(mode):
    data,main,session=setup(TYPES[0])
    if mode=='no_template':main.template=None
    elif mode=='other_stack':session.template.id='other'
    elif mode=='other_scope':session.scope.region='us-east-1'
    elif mode=='unknown_session':session.template.state='UNRESOLVED'
    elif mode=='duplicate':data.resources.append(template(target('another','AWS::Macie::Session')))
    elif mode=='missing':data.resources.remove(session)
    else:
        main.template.depends_on=[]
        link(data,main,'Description',session,'Maybe')
    assert evaluate_macie_session_order(data,main)[0]['verdict']=='NEEDS_REVIEW'


def test_cycle():
    data,main,session=setup(TYPES[0])
    session.template.depends_on=['main']
    assert evaluate_macie_session_order(data,main)[0]['verdict']=='FAIL'


def test_checker_dispatch():
    data,main,_=setup(TYPES[1])
    root=Path(__file__).resolve().parents[1]
    rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(data)['results']
    assert any(r['rule_id']=='MACIE_SESSION_DEPENDENCY' and r['verdict']=='PASS' for r in rows)
