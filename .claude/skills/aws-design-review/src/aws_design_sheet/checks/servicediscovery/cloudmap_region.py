"""Documented GovCloud exclusion for Cloud Map public DNS namespaces."""
from ..registry import resource_check
from ..common.context_values import _Context
from ..common.scoped_resolution import resolved

SOURCES={'CLOUDMAP_PUBLIC_DNS_GOVCLOUD':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-servicediscovery-publicdnsnamespace.html','https://docs.aws.amazon.com/cloud-map/latest/api/API_CreatePublicDnsNamespace.html']}


@resource_check('AWS::ServiceDiscovery::PublicDnsNamespace')
def evaluate_servicediscovery_cloudmap_region(design,resource):
    if resource.type!='AWS::ServiceDiscovery::PublicDnsNamespace':return []
    ctx=_Context(design,resource)
    verdict='NEEDS_REVIEW' if not resolved(resource) else 'FAIL' if resource.scope.region.startswith('us-gov-') else 'PASS'
    f=ctx.finding('CLOUDMAP_PUBLIC_DNS_GOVCLOUD','/scope/region',verdict,'CreatePublicDnsNamespace is not supported in AWS GovCloud (US) Regions. Use explicit resolved resource Region evidence. PASS only establishes that the documented GovCloud exclusion does not apply; it does not certify service availability, namespace uniqueness or DNS readiness.')
    f['source_checked_at']='2026-10-04';return [f]
