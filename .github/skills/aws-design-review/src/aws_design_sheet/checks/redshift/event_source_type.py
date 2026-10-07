"""Checks for AWS::Redshift::EventSubscription."""
from ..registry import resource_check
from ..common.event_subscription_sources import event_source_finding

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'REDSHIFT_EVENT_SOURCE_TYPE': [CF+'aws-resource-redshift-eventsubscription.html'],
}


@resource_check('AWS::Redshift::EventSubscription')
def evaluate_redshift_event_source_type(design,resource):return event_source_finding(design,resource)
