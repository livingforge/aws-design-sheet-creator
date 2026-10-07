import pytest
from aws_design_sheet.checks.emrserverless.worker_keys import evaluate_emrserverless_worker_keys
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('kind',['SPARK','Spark','Hive','HIVE','future',UNKNOWN])
@pytest.mark.parametrize('case',['complete','missing','extra','dynamic','unknown'])
def test_documented_required_subset(kind,case):
    keys=['HiveDriver','TezTask'] if kind in ('Hive','HIVE') else ['Driver','Executor']
    raw={k:{} for k in keys}
    if case=='missing':raw.pop(keys[1])
    if case=='extra':raw['FutureWorker']={}
    if case=='dynamic':raw={keys[0]:{},'${WorkerType}':{}}
    if case=='unknown':raw=UNKNOWN
    r=target('main','AWS::EMRServerless::Application',Type=kind,WorkerTypeSpecifications=raw)
    expected='NEEDS_REVIEW' if kind not in ('SPARK','Spark','Hive','HIVE') or case in ('dynamic','unknown') else 'FAIL' if case=='missing' else 'PASS'
    assert evaluate_emrserverless_worker_keys(linked_design(r),r)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::EMRServerless::Application',Type='SPARK',WorkerTypeSpecifications={'Driver':{}})
    assert any(f['rule_id']=='EMRSERVERLESS_WORKER_REQUIRED_KEYS' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
