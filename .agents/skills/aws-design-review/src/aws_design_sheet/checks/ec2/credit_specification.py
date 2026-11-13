"""CPU credit option values.

EC2 accepts only 'standard' and 'unlimited' as the CPU credit option of a burstable instance
and refuses anything else (InvalidCpuCredits.Malformed); cfn-lint 1.57.2 does not report it.
"""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EC2_CPU_CREDITS_VALUE': [CF + 'aws-properties-ec2-instance-creditspecification.html',
                              CF + 'aws-properties-ec2-launchtemplate-creditspecification.html',
                              'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreditSpecificationRequest.html'],
}
PATHS = {'AWS::EC2::Instance': '/properties/CreditSpecification/CPUCredits',
         'AWS::EC2::LaunchTemplate': '/properties/LaunchTemplateData/CreditSpecification/CpuCredits'}


@resource_check(*PATHS)
def evaluate_cpu_credits_value(design, resource):
    ctx = _Context(design, resource)
    path = PATHS[resource.type]
    credits = value(ctx, resource, path)
    if credits is ABSENT:
        return []
    if not literal(credits):
        return [ctx.finding('EC2_CPU_CREDITS_VALUE', path, 'NEEDS_REVIEW', 'the CPU credit option is unresolved')]
    verdict = 'PASS' if credits in ('standard', 'unlimited') else 'FAIL'
    return [ctx.finding('EC2_CPU_CREDITS_VALUE', path, verdict, "the CPU credit option is 'standard' or 'unlimited'")]
