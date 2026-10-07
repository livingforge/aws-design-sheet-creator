from pathlib import Path
import pytest
from aws_design_sheet.checks.cleanrooms.cross_column_constraints import evaluate_cleanrooms_cross_column_constraints
from aws_design_sheet.checks.cloudformation.guardhook_changeset_actions import evaluate_cloudformation_guardhook_changeset_actions
from aws_design_sheet.checks.cloudtrail.event_selectors import evaluate_cloudtrail_event_selectors
from aws_design_sheet.checks.codestarnotifications.notification_tag_keys import evaluate_codestarnotifications_notification_tag_keys
from aws_design_sheet.checks.registry import combine
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
selectors_checks=combine(evaluate_cleanrooms_cross_column_constraints,evaluate_cloudformation_guardhook_changeset_actions,evaluate_cloudtrail_event_selectors,evaluate_codestarnotifications_notification_tag_keys)


def check(kind,**props):
    r=target('subject',kind,**props)
    return selectors_checks(linked_design(r),r)


@pytest.mark.parametrize('kind',['ConfiguredTable','IntermediateTable'])
@pytest.mark.parametrize('allowed,identity,expected',[
    (['value'],['id'],'PASS'),(['id'],['id'],'FAIL'),([],['id'],'PASS'),
    ([UNKNOWN],['id'],'NEEDS_REVIEW'),(['id'],[UNKNOWN],'NEEDS_REVIEW'),
    (['id',UNKNOWN],['id'],'FAIL'),(['Id'],['id'],'PASS')])
def test_comparison(kind,allowed,identity,expected):
    custom={'ComparisonControls':{'AllowedLiteralComparisonColumns':allowed},'AggregationThresholds':[{'IdentityColumns':identity}]}
    assert check('AWS::CleanRooms::'+kind,AnalysisRules=[{'Policy':{'V1':{'Custom':custom}}}])[0]['verdict']==expected


@pytest.mark.parametrize('ops,actions,expected',[
    (['CHANGE_SET'],['CREATE'],'PASS'),(['CHANGE_SET'],['UPDATE'],'FAIL'),(['CHANGE_SET'],['CREATE','DELETE'],'FAIL'),
    (['CHANGE_SET'],UNKNOWN,'NEEDS_REVIEW'),(['CHANGE_SET','RESOURCE'],['UPDATE'],'NEEDS_REVIEW'),
    (UNKNOWN,['DELETE'],'NEEDS_REVIEW'),(['CHANGE_SET'],['CREATE',UNKNOWN],'NEEDS_REVIEW')])
def test_hook(ops,actions,expected):
    assert check('AWS::CloudFormation::GuardHook',TargetOperations=ops,TargetFilters={'Actions':actions})[0]['verdict']==expected


def test_hook_other_shapes():
    assert not check('AWS::CloudFormation::GuardHook',TargetOperations=['RESOURCE'],TargetFilters={'Actions':['UPDATE']})
    assert check('AWS::CloudFormation::GuardHook',TargetOperations=['CHANGE_SET'],TargetFilters={'Targets':[
        {'Action':'UPDATE','TargetName':'AWS::S3::Bucket'}]})[0]['verdict']=='NEEDS_REVIEW'


def field(name,**ops):return {'Field':name,**ops}


@pytest.mark.parametrize('fields,expected',[
    ([field('eventCategory',Equals=['Management'])],'PASS'),
    ([field('eventCategory',Equals=['Data']),field('resources.type',Equals=['AWS::S3::Object'])],'PASS'),
    ([field('eventCategory',Equals=['Data'])],'FAIL'),
    ([field('eventCategory',Equals=['NetworkActivity']),field('eventSource',Equals=['ec2.amazonaws.com'])],'PASS'),
    ([field('eventCategory',Equals=['NetworkActivity'])],'FAIL'),
    ([field('eventCategory',Equals=['NetworkActivity']),field('eventSource',StartsWith=['ec2'])],'FAIL'),
    ([field('readOnly',Equals=['true'])],'FAIL'),
    ([field('eventCategory',StartsWith=['Data'])],'FAIL'),
    ([field('eventCategory',Equals=['Management'],NotEquals=['Data'])],'FAIL'),
    ([field('eventCategory',Equals=['Data']),field('resources.type',Equals=['A']),field('resources.type',Equals=['B'])],'FAIL'),
    ([field('eventCategory',Equals=['Data']),field(UNKNOWN,Equals=['A'])],'NEEDS_REVIEW'),
    ([field('eventCategory',Equals=[UNKNOWN])],'NEEDS_REVIEW'),
    ([field('eventCategory',Equals=['Data','Management'])],'NEEDS_REVIEW'),
    ([field('eventCategory',Equals=['future'])],'FAIL'),
    (UNKNOWN,'NEEDS_REVIEW'),
    ([field('eventCategory',Equals=['Management']),field('readOnly',NotEquals=['false'])],'FAIL')])
def test_datastore(fields,expected):
    assert check('AWS::CloudTrail::EventDataStore',AdvancedEventSelectors=[{'FieldSelectors':fields}])[0]['verdict']==expected


@pytest.mark.parametrize('category',['Insight','ConfigurationItem','Evidence','ActivityAuditLog'])
def test_other_categories(category):
    assert check('AWS::CloudTrail::EventDataStore',AdvancedEventSelectors=[{'FieldSelectors':[
        field('eventCategory',Equals=[category])]}])[0]['verdict']=='PASS'


@pytest.mark.parametrize('count,unknown,expected',[(499,False,'PASS'),(500,False,'PASS'),(501,False,'FAIL'),(500,True,'NEEDS_REVIEW'),(501,True,'FAIL')])
def test_trail_limit(count,unknown,expected):
    # Count across multiple selectors/operators, including repeated literal values.
    selectors=[{'FieldSelectors':[field('eventName',Equals=['a']*250)]},
               {'FieldSelectors':[field('eventName',StartsWith=['b']*(count-250),**({'NotEquals':UNKNOWN} if unknown else {}))]}]
    assert check('AWS::CloudTrail::Trail',AdvancedEventSelectors=selectors)[0]['verdict']==expected


@pytest.mark.parametrize('tags,expected',[({'aws:x':'v'},'FAIL'),({'awsanything':'v'},'FAIL'),({'team':'v'},'PASS'),
    ({'AWS:x':'v'},'NEEDS_REVIEW'),({'${key}':'v'},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_codestar(tags,expected):
    assert check('AWS::CodeStarNotifications::NotificationRule',Tags=tags)[0]['verdict']==expected


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::CloudTrail::EventDataStore',AdvancedEventSelectors=[{'FieldSelectors':[field('eventCategory',Equals=['Data'])]}])
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    row=next(r for r in result['results'] if r['rule_id']=='CLOUDTRAIL_DATASTORE_SELECTORS')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
