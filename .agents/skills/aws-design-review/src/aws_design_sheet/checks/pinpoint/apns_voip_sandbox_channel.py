"""Checks for AWS::Pinpoint::APNSVoipSandboxChannel."""
from ..registry import resource_check
from ..common.catalog_values import catalog_value


@resource_check('AWS::Pinpoint::APNSVoipSandboxChannel')
def evaluate_pinpoint_apns_voip_sandbox_channel(design,resource):return catalog_value(design,resource)
