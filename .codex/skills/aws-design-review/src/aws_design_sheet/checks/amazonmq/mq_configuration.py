"""Known engine-family compatibility of explicitly linked MQ configurations."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'AMAZONMQ_CONFIGURATION_ENGINE':[CF+'aws-resource-amazonmq-configuration.html',CF+'aws-resource-amazonmq-broker.html'],
 'AMAZONMQ_ASSOCIATION_ENGINE':[CF+'aws-resource-amazonmq-configurationassociation.html',CF+'aws-resource-amazonmq-configuration.html',CF+'aws-resource-amazonmq-broker.html'],
}


def engine_pair(ctx,broker,config):
    if not resolved(broker) or not resolved(config):return 'NEEDS_REVIEW'
    a=value(ctx,broker,'/properties/EngineType');b=value(ctx,config,'/properties/EngineType')
    if a not in ('ACTIVEMQ','RABBITMQ') or b not in ('ACTIVEMQ','RABBITMQ'):return 'NEEDS_REVIEW'
    return 'PASS' if a==b else 'FAIL'


@resource_check('AWS::AmazonMQ::ConfigurationAssociation', 'AWS::AmazonMQ::Configuration')
def evaluate_amazonmq_mq_configuration(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict):
        f=ctx.finding(rule,path,verdict,'explicit known-scope broker/configuration links must use the same engine family; version compatibility, revision history, conflicting update order and availability remain open')
        f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::AmazonMQ::ConfigurationAssociation':
        broker=linked(ctx,resource,'/properties/Broker','AWS::AmazonMQ::Broker')
        config=linked(ctx,resource,'/properties/Configuration/Id','AWS::AmazonMQ::Configuration')
        emit('AMAZONMQ_ASSOCIATION_ENGINE','/properties/Configuration/Id',engine_pair(ctx,broker,config) if resolved(resource) else 'NEEDS_REVIEW')
    if resource.type=='AWS::AmazonMQ::Configuration':
        observed=False;pending=False;failed=False
        for source in design.resources:
            if source.scope!=resource.scope or source.type not in ('AWS::AmazonMQ::Broker','AWS::AmazonMQ::ConfigurationAssociation'):continue
            dest=linked(ctx,source,'/properties/Configuration/Id','AWS::AmazonMQ::Configuration')
            if not resolved(dest) or not resolved(source):pending=True;continue
            if dest.id!=resource.id:continue
            observed=True
            broker=source if source.type=='AWS::AmazonMQ::Broker' else linked(ctx,source,'/properties/Broker','AWS::AmazonMQ::Broker')
            v=engine_pair(ctx,broker,resource);failed|=v=='FAIL';pending|=v=='NEEDS_REVIEW'
        emit('AMAZONMQ_CONFIGURATION_ENGINE','/properties/EngineType','FAIL' if failed else 'PASS' if observed and not pending else 'NEEDS_REVIEW')
    return results
