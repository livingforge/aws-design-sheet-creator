"""Checks for AWS::Personalize::Dataset, AWS::Personalize::EventTracker."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import known_scope, literal

LIMITS={
 'AWS::KinesisAnalyticsV2::ApplicationCloudWatchLoggingOption':('KINESISANALYTICS_LOGGING_SINGLE','ApplicationName','AWS::KinesisAnalyticsV2::Application',None),
 'AWS::Personalize::Dataset':('PERSONALIZE_DATASET_TYPE_SINGLE','DatasetGroupArn','AWS::Personalize::DatasetGroup','DatasetType'),
 'AWS::Personalize::EventTracker':('PERSONALIZE_EVENT_TRACKER_SINGLE','DatasetGroupArn','AWS::Personalize::DatasetGroup',None),
 'AWS::Route53Profiles::ProfileAssociation':('ROUTE53PROFILES_VPC_SINGLE','ResourceId','AWS::EC2::VPC',None),
 'AWS::SecurityLake::SubscriberNotification':('SECURITYLAKE_NOTIFICATION_SINGLE','SubscriberArn','AWS::SecurityLake::Subscriber',None)}
SOURCES = {
    'PERSONALIZE_DATASET_TYPE_SINGLE': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-personalize-dataset.html',
    ],
    'PERSONALIZE_EVENT_TRACKER_SINGLE': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-personalize-eventtracker.html',
    ],
}


@resource_check('AWS::Personalize::Dataset', 'AWS::Personalize::EventTracker')
def evaluate_personalize_dataset_links(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type in LIMITS:
        rule,key,kind,variant=LIMITS[resource.type];p='/properties/'+key;own=linked(ctx,resource,p,kind);duplicate=False
        own_variant=get('/properties/'+variant) if variant else True
        if own and known_scope(resource) and (not variant or literal(own_variant)):
            for other in design.resources:
                if other.id==resource.id or other.type!=resource.type or other.scope!=resource.scope:continue
                parent=linked(ctx,other,p,kind)
                if parent and parent.id==own.id and (not variant or value(ctx,other,'/properties/'+variant)==own_variant):duplicate=True
        emit(rule,p,'FAIL' if duplicate else 'NEEDS_REVIEW','proves more than one explicit association to the same unconditionally linked parent, and same DatasetType where applicable; unknown/literal parent, other scopes and external associations remain held; no global PASS')
    return results
