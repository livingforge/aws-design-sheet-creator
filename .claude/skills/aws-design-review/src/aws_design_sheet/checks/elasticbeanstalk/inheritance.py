"""Bounded effective solution stack resolution for explicit Beanstalk references."""
from ..common.context_values import linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved


def effective_stack(ctx,r,app_matches,seen=None):
    seen=set() if seen is None else seen
    if not resolved(r) or r.id in seen or len(seen)>=32:return None
    seen=seen|{r.id}
    own=value(ctx,r,'/properties/SolutionStackName')
    if literal(own):return own
    if own is not ABSENT or value(ctx,r,'/properties/PlatformArn') is not ABSENT:return None
    if r.type=='AWS::ElasticBeanstalk::Environment':
        other=linked(ctx,r,'/properties/TemplateName','AWS::ElasticBeanstalk::ConfigurationTemplate')
        if not resolved(other) or not app_matches(ctx,r,'/properties/ApplicationName',other,'/properties/ApplicationName'):return None
    elif r.type=='AWS::ElasticBeanstalk::ConfigurationTemplate':
        source=value(ctx,r,'/properties/SourceConfiguration');env=value(ctx,r,'/properties/EnvironmentId')
        if source is not ABSENT and env is not ABSENT:return None
        if source is not ABSENT:
            other=linked(ctx,r,'/properties/SourceConfiguration/TemplateName',r.type)
            if not resolved(other) or not app_matches(ctx,r,'/properties/SourceConfiguration/ApplicationName',other,'/properties/ApplicationName'):return None
        else:
            other=linked(ctx,r,'/properties/EnvironmentId','AWS::ElasticBeanstalk::Environment')
    else:return None
    return effective_stack(ctx,other,app_matches,seen)
