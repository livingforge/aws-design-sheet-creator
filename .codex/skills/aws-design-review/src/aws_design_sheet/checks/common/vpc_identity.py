"""VPC identity of a resource from a linked VPC or a literal VPC ID."""
from .context_values import linked, value
from .scoped_resolution import resolved
from .vpc_ids import vpc_id


def vpc_identity(ctx,r):
    if not resolved(r):return None
    vpc=linked(ctx,r,'/properties/VpcId','AWS::EC2::VPC')
    if resolved(vpc):return ('resource',vpc.id)
    raw=value(ctx,r,'/properties/VpcId')
    return ('literal',raw) if vpc_id(raw) else None
