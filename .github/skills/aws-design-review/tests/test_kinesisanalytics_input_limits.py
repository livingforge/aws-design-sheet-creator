import pytest
from aws_design_sheet.checks.kinesisanalytics.input_limits import evaluate_kinesisanalytics_input_limits, STRINGS, ROOT, SCHEMA
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def build(path,raw):
    for part in reversed(path.split('/')):raw=[raw] if part=='*' else {part:raw}
    return raw


@pytest.mark.parametrize('suffix,low,high,pattern',STRINGS)
@pytest.mark.parametrize('case',['minimum','empty','maximum','overflow','unknown','dynamic','invalid_pattern'])
def test_strings(suffix,low,high,pattern,case):
    raw='UTF-8' if pattern=='UTF-8' else 'arn:' if pattern==r'arn:.*' else 'a'*low
    expected='PASS'
    if case=='empty':raw='';expected='FAIL' if low or pattern else 'PASS'
    if case in ('maximum','overflow') and pattern!='UTF-8':
        prefix='arn:' if pattern==r'arn:.*' else ''
        raw=prefix+'a'*((high or 3000)+(case=='overflow')-len(prefix))
        expected='FAIL' if case=='overflow' and high is not None else 'PASS'
    if case=='unknown':raw=UNKNOWN;expected='NEEDS_REVIEW'
    if case=='dynamic':raw='${value}';expected='NEEDS_REVIEW'
    if case=='invalid_pattern':raw='!';expected='FAIL' if pattern else 'PASS'
    r=target('main','AWS::KinesisAnalytics::Application',**build(suffix,raw))
    path='/properties/'+suffix.replace('*','0')
    found=[f for f in evaluate_kinesisanalytics_input_limits(linked_design(r),r) if f['path']==path]
    assert len(found)==1 and found[0]['verdict']==expected


@pytest.mark.parametrize('suffix,limit,collection',[(ROOT+'InputParallelism/Count',64,False),(SCHEMA+'RecordColumns',1000,True)])
@pytest.mark.parametrize('case',['zero','min','max','overflow','unknown','bool','float'])
def test_count(suffix,limit,collection,case):
    raw={'zero':0,'min':1,'max':limit,'overflow':limit+1,'unknown':UNKNOWN,'bool':True,'float':1.5}[case]
    if collection and type(raw) is int:raw=[{}]*raw
    r=target('main','AWS::KinesisAnalytics::Application',**build(suffix,raw))
    found=[f for f in evaluate_kinesisanalytics_input_limits(linked_design(r),r) if f['path']=='/properties/'+suffix.replace('*','0')]
    expected='FAIL' if case in ('zero','overflow') else 'PASS' if case in ('min','max') else 'NEEDS_REVIEW'
    assert len(found)==1 and found[0]['verdict']==expected


@pytest.mark.parametrize('parent',['Inputs','Inputs/*/InputSchema/RecordColumns'])
def test_string_instead_of_collection_is_not_a_leaf(parent):
    r=target('main','AWS::KinesisAnalytics::Application',**build(parent,'wrong-shape'))
    found=evaluate_kinesisanalytics_input_limits(linked_design(r),r)
    assert found and all(f['verdict']=='NEEDS_REVIEW' for f in found)


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::KinesisAnalytics::Application',Inputs=[{'InputParallelism':{'Count':65}}])
    found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='KINESIS_ANALYTICS_INPUT_LEAF_LIMITS' and f['verdict']=='FAIL' for f in found)
