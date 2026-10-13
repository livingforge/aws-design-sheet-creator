"""Checks for AWS::Pinpoint::Segment."""
from ..registry import resource_check
from ..common.enum_findings import enum_findings


@resource_check('AWS::Pinpoint::Segment')
def evaluate_pinpoint_segment(design,resource):return enum_findings(design,resource)
