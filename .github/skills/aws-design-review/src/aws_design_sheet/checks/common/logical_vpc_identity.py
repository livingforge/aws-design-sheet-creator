"""Logical VPC identity that is not established by a literal deployed ID."""
from .context_values import linked
from .field_reads import ABSENT, read
from .scoped_resolution import resolved
from .vpc_identity import vpc_identity


def identity(ctx,r):
    if not resolved(r):return None
    # A literal deployed ID cannot establish the identity of a logical VPC.
    if linked(ctx,r,'/properties/VpcId','AWS::EC2::VPC') and read(ctx,r,'/properties/VpcId') is not ABSENT:return None
    return vpc_identity(ctx,r)
