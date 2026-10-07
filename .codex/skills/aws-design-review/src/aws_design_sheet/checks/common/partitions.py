"""AWS partition of a Region."""
import re


def public_partition(region):
    if re.fullmatch(r'cn-[a-z]+-\d+', region):
        return 'aws-cn'
    if re.fullmatch(r'us-gov-[a-z]+-\d+', region):
        return 'aws-us-gov'
    if re.fullmatch(r'(?:af|ap|ca|eu|il|me|mx|sa|us)-(?!iso)[a-z]+-\d+', region):
        return 'aws'
    return None
