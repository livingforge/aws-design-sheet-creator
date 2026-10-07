import pytest
from aws_design_sheet.checks.config.recorder_order import evaluate_config_recorder_order
from test_autoscaling_group_and_scaling_policy import target, linked_design
from test_template_dependencies import template


def fixture():
    channel = template(target('channel','AWS::Config::DeliveryChannel'),['recorder'])
    recorder = template(target('recorder','AWS::Config::ConfigurationRecorder'),[])
    return linked_design(channel,[recorder]),channel,recorder


@pytest.mark.parametrize('case,want', [('ordered','PASS'),('missing','FAIL'),('unknown','NEEDS_REVIEW'),('cycle','FAIL'),('external','NEEDS_REVIEW'),('other_template','NEEDS_REVIEW'),('no_template','NEEDS_REVIEW'),('other_region','NEEDS_REVIEW'),('ambiguous','NEEDS_REVIEW')])
def test_recorder_order(case,want):
    d,c,r = fixture()
    if case == 'missing': c.template.depends_on = []
    if case == 'unknown': c.template.depends_on = None
    if case == 'cycle': r.template.depends_on = ['channel']
    if case == 'external': d.resources.remove(r)
    if case == 'other_template': r.template.id = 'other'
    if case == 'no_template': c.template = None
    if case == 'other_region': r.scope.region = 'us-west-2'
    if case == 'ambiguous': d.resources.append(template(target('recorder2',r.type),[]))
    assert evaluate_config_recorder_order(d,c)[0]['verdict'] == want


def test_transitive_order():
    d,c,r = fixture()
    helper = template(target('helper','AWS::S3::Bucket'),['recorder'])
    c.template.depends_on = ['helper']
    d.resources.append(helper)
    assert evaluate_config_recorder_order(d,c)[0]['verdict'] == 'PASS'


def test_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,c,r = fixture()
    root = Path(__file__).resolve().parents[1]
    findings = Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='CONFIG_CHANNEL_RECORDER_ORDER' and f['verdict']=='PASS' for f in findings)
