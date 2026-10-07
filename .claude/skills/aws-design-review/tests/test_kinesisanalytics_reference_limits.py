import pytest
from aws_design_sheet.checks.kinesisanalytics.reference_limits import evaluate_kinesisanalytics_reference_limits, SPECS
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_config_pipeline import nested


@pytest.mark.parametrize('suffix,low,high,pattern',SPECS)
@pytest.mark.parametrize('case',['minimum','empty','maximum','overflow','unknown','dynamic'])
def test_boundaries(suffix,low,high,pattern,case):
    prefix='arn:' if pattern==r'arn:.*' else ''
    raw=prefix+'a'
    expected='PASS'
    if case=='empty':raw='';expected='FAIL'
    if case=='maximum':raw=prefix+'a'*((high or 3000)-len(prefix))
    if case=='overflow':raw=prefix+'a'*((high or 3000)+1-len(prefix));expected='FAIL' if high else 'PASS'
    if case=='unknown':raw=UNKNOWN;expected='NEEDS_REVIEW'
    if case=='dynamic':raw='${value}';expected='NEEDS_REVIEW'
    parts=suffix.split('/')
    if '*' in parts:
        i=parts.index('*');props=nested(parts[:i],[nested(parts[i+1:],raw)])
    else:props=nested(parts,raw)
    r=target('main','AWS::KinesisAnalytics::ApplicationReferenceDataSource',**props)
    findings=evaluate_kinesisanalytics_reference_limits(linked_design(r),r)
    assert len(findings)==1 and findings[0]['verdict']==expected


@pytest.mark.parametrize('raw,expected',[('\n','PASS'),('\r\n','PASS'),('', 'FAIL')])
def test_csv_row_delimiter_can_be_newline(raw,expected):
    r=target('main','AWS::KinesisAnalytics::ApplicationReferenceDataSource',ReferenceDataSource={'ReferenceSchema':{'RecordFormat':{'MappingParameters':{'CSVMappingParameters':{'RecordRowDelimiter':raw}}}}})
    assert evaluate_kinesisanalytics_reference_limits(linked_design(r),r)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::KinesisAnalytics::ApplicationReferenceDataSource',ReferenceDataSource={'TableName':'a'*33})
    found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='KINESIS_ANALYTICS_REFERENCE_STRING_LIMITS' and f['verdict']=='FAIL' for f in found)


def test_string_instead_of_columns_is_not_sql_type():
    r=target('main','AWS::KinesisAnalytics::ApplicationReferenceDataSource',ReferenceDataSource={'ReferenceSchema':{'RecordColumns':'wrong-shape'}})
    found=evaluate_kinesisanalytics_reference_limits(linked_design(r),r)
    assert len(found)==1 and found[0]['verdict']=='NEEDS_REVIEW'
