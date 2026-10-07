import pytest
from aws_design_sheet.checks.fsx.flexvol_aggregate import evaluate_fsx_flexvol_aggregate
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('style,aggregates,expected',[
    ('FLEXVOL',['aggr1'],'PASS'),('FLEXVOL',['aggr1','aggr2'],'FAIL'),('FLEXVOL',[],'FAIL'),('FLEXVOL',[UNKNOWN],'PASS'),
    ('FLEXVOL',UNKNOWN,'NEEDS_REVIEW'),('FLEXGROUP',['aggr1','aggr2'],'NOT_APPLICABLE'),(UNKNOWN,['aggr1'],'NEEDS_REVIEW'),
])
def test_cardinality_only(style,aggregates,expected):
    r=target('main','AWS::FSx::Volume',VolumeType='ONTAP',OntapConfiguration={'VolumeStyle':style,'AggregateConfiguration':{'Aggregates':aggregates}})
    assert evaluate_fsx_flexvol_aggregate(linked_design(r),r)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::FSx::Volume',VolumeType='ONTAP',OntapConfiguration={'VolumeStyle':'FLEXVOL','AggregateConfiguration':{'Aggregates':['aggr1','aggr2']}})
    assert any(f['rule_id']=='FSX_FLEXVOL_SINGLE_AGGREGATE' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
