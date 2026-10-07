"""Literal VPC ID format."""
import re
from .literals import literal


def vpc_id(raw):
    return literal(raw) and re.fullmatch(r'vpc-(?:[0-9a-f]{8}|[0-9a-f]{17})',raw) is not None
