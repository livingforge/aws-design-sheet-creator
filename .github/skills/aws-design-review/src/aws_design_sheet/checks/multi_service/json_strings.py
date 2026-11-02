"""JSON syntax of string properties whose AWS documentation says they hold JSON.

Only properties that neither cfn-lint 1.57.2 nor another check here flags when the
JSON is broken. A property also typed as an object is checked only when given as a string.
"""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.json_verdict import json_verdict
from ..common.literals import expand

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
JSON_STRINGS = {  # type -> (rule, property pattern, documentation page)
    'AWS::StepFunctions::StateMachine': [('STEPFUNCTIONS_DEFINITION_STRING_JSON', 'DefinitionString', 'aws-resource-stepfunctions-statemachine.html')],
    'AWS::Logs::ResourcePolicy': [('LOGS_RESOURCE_POLICY_JSON', 'PolicyDocument', 'aws-resource-logs-resourcepolicy.html')],
    'AWS::Logs::Destination': [('LOGS_DESTINATION_POLICY_JSON', 'DestinationPolicy', 'aws-resource-logs-destination.html')],
    'AWS::Events::Rule': [('EVENTS_TARGET_INPUT_JSON', 'Targets/*/Input', 'aws-properties-events-rule-target.html')],
    'AWS::DMS::ReplicationTask': [('DMS_TABLE_MAPPINGS_JSON', 'TableMappings', 'aws-resource-dms-replicationtask.html'),
                                  ('DMS_REPLICATION_TASK_SETTINGS_JSON', 'ReplicationTaskSettings', 'aws-resource-dms-replicationtask.html')],
    'AWS::Glue::Crawler': [('GLUE_CRAWLER_CONFIGURATION_JSON', 'Configuration', 'aws-resource-glue-crawler.html')],
    'AWS::Bedrock::Flow': [('BEDROCK_FLOW_DEFINITION_STRING_JSON', 'DefinitionString', 'aws-resource-bedrock-flow.html')],
    'AWS::CE::AnomalySubscription': [('CE_THRESHOLD_EXPRESSION_JSON', 'ThresholdExpression', 'aws-resource-ce-anomalysubscription.html')],
    'AWS::CE::CostCategory': [('CE_COST_CATEGORY_RULES_JSON', 'Rules', 'aws-resource-ce-costcategory.html')],
    'AWS::Connect::ContactFlow': [('CONNECT_CONTACT_FLOW_CONTENT_JSON', 'Content', 'aws-resource-connect-contactflow.html')],
    'AWS::Connect::ContactFlowModule': [('CONNECT_FLOW_MODULE_CONTENT_JSON', 'Content', 'aws-resource-connect-contactflowmodule.html'),
                                        ('CONNECT_FLOW_MODULE_SETTINGS_JSON', 'Settings', 'aws-resource-connect-contactflowmodule.html')],
    'AWS::OpenSearchServerless::AccessPolicy': [('OPENSEARCHSERVERLESS_ACCESS_POLICY_JSON', 'Policy', 'aws-resource-opensearchserverless-accesspolicy.html')],
    'AWS::OpenSearchServerless::LifecyclePolicy': [('OPENSEARCHSERVERLESS_LIFECYCLE_POLICY_JSON', 'Policy', 'aws-resource-opensearchserverless-lifecyclepolicy.html')],
    'AWS::RUM::AppMonitor': [('RUM_RESOURCE_POLICY_JSON', 'ResourcePolicy/PolicyDocument', 'aws-properties-rum-appmonitor-resourcepolicy.html')],
    'AWS::RDS::CustomDBEngineVersion': [('RDS_CEV_MANIFEST_JSON', 'Manifest', 'aws-resource-rds-customdbengineversion.html')],
    'AWS::IoTSiteWise::Gateway': [('IOTSITEWISE_CAPABILITY_CONFIGURATION_JSON', 'GatewayCapabilitySummaries/*/CapabilityConfiguration', 'aws-resource-iotsitewise-gateway.html')],
    'AWS::Route53Profiles::ProfileResourceAssociation': [('ROUTE53PROFILES_RESOURCE_PROPERTIES_JSON', 'ResourceProperties', 'aws-resource-route53profiles-profileresourceassociation.html')],
    'AWS::Personalize::Schema': [('PERSONALIZE_SCHEMA_JSON', 'Schema', 'aws-resource-personalize-schema.html')],
    'AWS::PaymentCryptography::Key': [('PAYMENTCRYPTOGRAPHY_KEY_POLICY_JSON', 'Policy', 'aws-resource-paymentcryptography-key.html')],
    'AWS::EventsV2::Subscriber': [('EVENTSV2_FILTER_PATTERN_JSON', 'FilterConfiguration/Filters/*/Pattern', 'aws-resource-eventsv2-subscriber.html')],
    'AWS::SQS::Queue': [('SQS_REDRIVE_POLICY_JSON', 'RedrivePolicy', 'aws-resource-sqs-queue.html')],
    'AWS::SNS::Subscription': [('SNS_FILTER_POLICY_JSON', 'FilterPolicy', 'aws-resource-sns-subscription.html')],
}
SOURCES = {rule: [CF + page] for specs in JSON_STRINGS.values() for rule, _, page in specs}


@resource_check(*JSON_STRINGS)
def documented_json_strings(design, resource):
    ctx = _Context(design, resource)
    results = []
    for rule, pattern, _ in JSON_STRINGS[resource.type]:
        for path in expand(ctx, resource, '/properties/' + pattern):
            raw = value(ctx, resource, path)
            if isinstance(raw, (dict, list)):
                continue  # an object form, or an array not yet expanded, is not a JSON string
            finding = ctx.finding(rule, path, json_verdict(raw),
                'the documented JSON string must parse; substitutions and unknown values need review, and the content structure is not checked')
            finding['source_checked_at'] = '2026-11-01'
            results.append(finding)
    return results
