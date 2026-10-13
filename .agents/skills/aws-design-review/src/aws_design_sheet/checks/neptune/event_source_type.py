"""Checks for AWS::Neptune::EventSubscription."""
from ..registry import resource_check
from ..common.event_subscription_sources import event_source_finding

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'NEPTUNE_EVENT_SOURCE_TYPE': [CF+'aws-resource-neptune-eventsubscription.html','https://docs.aws.amazon.com/neptune/latest/apiref/API_CreateEventSubscription.html'],
}


@resource_check('AWS::Neptune::EventSubscription')
def evaluate_neptune_event_source_type(design,resource):return event_source_finding(design,resource)
