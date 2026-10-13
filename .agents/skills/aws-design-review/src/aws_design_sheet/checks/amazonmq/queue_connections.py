"""Checks for AWS::AmazonMQ::Broker, AWS::AmazonMQ::Configuration."""
import base64
import re
from xml.etree.ElementTree import ParseError
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.key_types_and_base64 import base64_syntax
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'AMAZONMQ_SUBNET_COUNT': [CF+'aws-resource-amazonmq-broker.html'],
    'AMAZONMQ_SUBNET_AZ': [CF+'aws-resource-amazonmq-broker.html'],
    'AMAZONMQ_ACTIVEMQ_XML': [CF+'aws-resource-amazonmq-configuration.html'],
}


def mq_count(ctx, r):
    subnets = value(ctx, r, '/properties/SubnetIds')
    if not isinstance(subnets, list):
        return 'NEEDS_REVIEW'
    engine = value(ctx, r, '/properties/EngineType')
    mode = value(ctx, r, '/properties/DeploymentMode')
    if engine not in ('ACTIVEMQ', 'RABBITMQ'):
        return 'NEEDS_REVIEW'
    if mode == 'SINGLE_INSTANCE':
        return 'PASS' if len(subnets) == 1 else 'FAIL'
    if engine == 'ACTIVEMQ' and mode == 'ACTIVE_STANDBY_MULTI_AZ':
        return 'PASS' if len(subnets) == 2 else 'FAIL'
    if engine == 'RABBITMQ' and mode == 'CLUSTER_MULTI_AZ':
        public = value(ctx, r, '/properties/PubliclyAccessible')
        if public is True:
            return 'NOT_APPLICABLE'
        if public is False:
            return 'PASS' if subnets else 'FAIL'
    return 'NEEDS_REVIEW'


def mq_zones(ctx, r):
    subnets = value(ctx, r, '/properties/SubnetIds')
    if not resolved(r) or not isinstance(subnets, list) or len(subnets) < 2:
        return 'NEEDS_REVIEW'
    zones = []
    for i in range(len(subnets)):
        subnet = linked(ctx, r, '/properties/SubnetIds/'+str(i), 'AWS::EC2::Subnet')
        if not resolved(subnet):
            return 'NEEDS_REVIEW'
        zone = value(ctx, subnet, '/properties/AvailabilityZone')
        if not literal(zone) or not re.fullmatch(re.escape(r.scope.region)+r'[a-z]', zone):
            return 'NEEDS_REVIEW'
        zones.append(zone)
    return 'PASS' if len(zones) == len(set(zones)) else 'FAIL'


def mq_xml(raw):
    if base64_syntax(raw) != 'PASS':
        return 'NEEDS_REVIEW'
    data = base64.b64decode(raw, validate=True)
    try:
        # DTD/entity constructs are conservatively held, not interpreted.
        root = ElementTree.fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        stack = [(root, 0)]; count = 0
        while stack:
            node, depth = stack.pop(); count += 1
            if depth > 64 or count > 10000:
                return 'NEEDS_REVIEW'
            stack.extend((child, depth+1) for child in node)
        return 'PASS'
    except DefusedXmlException:
        return 'NEEDS_REVIEW'
    except (ParseError, ValueError):
        return 'FAIL'


@resource_check('AWS::AmazonMQ::Broker', 'AWS::AmazonMQ::Configuration')
def evaluate_amazonmq_queue_connections(design, resource):
    ctx = _Context(design, resource); results = []
    def emit(rule, path, verdict, reason):
        f = ctx.finding(rule, path, verdict, reason); f['source_checked_at'] = '2026-10-04'; results.append(f)
    if resource.type == 'AWS::AmazonMQ::Broker' and value(ctx, resource, '/properties/SubnetIds') is not ABSENT:
        emit('AMAZONMQ_SUBNET_COUNT', '/properties/SubnetIds', mq_count(ctx, resource), 'explicit subnet count by documented engine/deployment/public mode; omitted default subnets, unsupported modes, network ownership and availability remain open')
        emit('AMAZONMQ_SUBNET_AZ', '/properties/SubnetIds', mq_zones(ctx, resource), 'all explicit linked ordinary AZ names must differ; unknown/external/conditional links, AZ IDs, local zones and network ownership held')
    if resource.type == 'AWS::AmazonMQ::Configuration':
        path = '/properties/Data'; raw = value(ctx, resource, path)
        if raw is not ABSENT:
            engine = value(ctx, resource, '/properties/EngineType')
            emit('AMAZONMQ_ACTIVEMQ_XML', path, mq_xml(raw) if engine == 'ACTIVEMQ' else 'NEEDS_REVIEW', 'bounded canonical Base64-decoded ActiveMQ XML syntax only; DTD/entities, RabbitMQ Cuttlefish, engine-specific element/attribute support and runtime compatibility remain open')
    return results
