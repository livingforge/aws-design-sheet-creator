import pytest
from aws_design_sheet.checks.medialive.multiplex_numbers import evaluate_medialive_multiplex_numbers
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(number=12):
    r=target('a','AWS::MediaLive::Multiplexprogram',MultiplexId='1234567',ProgramName='news',MultiplexProgramSettings={'ProgramNumber':number})
    other=target('b',r.type,MultiplexId='1234567',ProgramName='sports',MultiplexProgramSettings={'ProgramNumber':number})
    return linked_design(r,[other]),r,other


def verdict(d,r):return evaluate_medialive_multiplex_numbers(d,r)[0]['verdict']


@pytest.mark.parametrize('number,want',[(0,'FAIL'),(65535,'FAIL'),(12,'FAIL'),(True,'NEEDS_REVIEW'),('12','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_known_number_collision(number,want):
    d,r,*_=fixture(number);assert verdict(d,r)==want


@pytest.mark.parametrize('mode',['different_number','different_mux','scope','same_name','unknown_name','missing_peer','unknown_number'])
def test_no_collision_does_not_prove_uniqueness(mode):
    d,r,o=fixture()
    if mode=='different_number':o.fields[2].candidates[0].value['ProgramNumber']=13
    if mode=='different_mux':o.fields[0].candidates[0].value='7654321'
    if mode=='scope':o.scope.account='222222222222'
    if mode=='same_name':o.fields[1].candidates[0].value='news'
    if mode=='unknown_name':o.fields[1].candidates[0].value=UNKNOWN
    if mode=='missing_peer':d.resources.remove(o)
    if mode=='unknown_number':o.fields[2].candidates[0].value['ProgramNumber']=UNKNOWN
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_logical_multiplex():
    d,r,o=fixture();mux=target('mux','AWS::MediaLive::Multiplex');d.resources.append(mux)
    for x in (r,o):x.fields.pop(0);link(d,x,'MultiplexId',mux)
    assert verdict(d,r)=='FAIL'
    d.relations[1].condition='Maybe'
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="MEDIALIVE_MULTIPLEX_PROGRAM_NUMBER_COLLISION" and f["verdict"]=="FAIL" for f in results)
