"""Checks for these resource types:

- AWS::WAF::SizeConstraintSet
- AWS::WAF::XssMatchSet
- AWS::WAFRegional::SqlInjectionMatchSet
"""
from ..registry import resource_check
from ..common.enum_findings import enum_findings


@resource_check('AWS::WAF::SizeConstraintSet','AWS::WAF::XssMatchSet')
def evaluate_waf_match_set_enums(design,resource):return enum_findings(design,resource)


@resource_check('AWS::WAFRegional::SqlInjectionMatchSet')
def evaluate_wafregional_match_set_enums(design,resource):return enum_findings(design,resource)
