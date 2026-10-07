import pytest
from aws_design_sheet.checks.cognito.mappings import evaluate_cognito_mappings
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('attribute,want', [(a,'PASS') for a in 'name family_name given_name middle_name nickname preferred_username profile picture website gender birthdate zoneinfo locale'.split()]+[(a,'FAIL') for a in 'email phone_number sub address updated_at custom:department'.split()])
def test_exact_profile_membership(attribute,want):
    assert result(attribute,['oidc:profile']) == want


def result(attribute,writes):
    p=target('pool','AWS::Cognito::UserPool')
    idp=target('idp','AWS::Cognito::UserPoolIdentityProvider',ProviderName='IdP',AttributeMapping={attribute:'claim'})
    c=target('client','AWS::Cognito::UserPoolClient',SupportedIdentityProviders=['IdP'],WriteAttributes=writes)
    d=linked_design(c,[p,idp]);link(d,c,'UserPoolId',p);link(d,idp,'UserPoolId',p)
    return next(f['verdict'] for f in evaluate_cognito_mappings(d,c) if f['rule_id']=='COGNITO_CLIENT_MAPPED_WRITE_ATTRIBUTES')


def test_explicit_addition_and_unknown_scope():
    assert result('email',['oidc:profile','email']) == 'PASS'
    assert result('email',['oidc:unknown']) == 'NEEDS_REVIEW'
    assert result('name',['oidc:profile',UNKNOWN]) == 'NEEDS_REVIEW'
