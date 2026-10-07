import pytest
from aws_design_sheet.checks.lex.regex_operators import operators, evaluate_lex_regex_operators
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('raw,expected',[
 ('[A-Z]{2,5}[0-9]?','PASS'),('a*','FAIL'),('a+','FAIL'),('a{2,}','FAIL'),('a{,}','FAIL'),('a.','FAIL'),
 (r'a\*','PASS'),(r'\+','PASS'),(r'\.','PASS'),('[*+.]','PASS'),('[]+.]','PASS'),
 ('[^*+.]{2}','PASS'),(r'\u0041{2,3}','PASS'),('(ab|cd){1,2}','PASS'),
 ('a{2}','PASS'),('a{2,3}?','PASS'),('a*?','FAIL'),('a{2,3}+','NEEDS_REVIEW'),
 ('a?+','NEEDS_REVIEW'),('(?x)a # .','NEEDS_REVIEW'),('(?#.)a','NEEDS_REVIEW'),
 ('(?=.)a','NEEDS_REVIEW'),(r'\Q.\E','NEEDS_REVIEW'),('[a','NEEDS_REVIEW'),
 ('[[]','NEEDS_REVIEW'),('a\\','NEEDS_REVIEW'),('a{3,2}','NEEDS_REVIEW'),
 ('${Pattern}','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),('a'*301,'NEEDS_REVIEW')])
def test_regex_operator_scanner(raw,expected):
    assert operators(raw)==expected


def test_nested_filter_and_unknown_ancestor():
    r=target('main','AWS::Lex::Bot',BotLocales=[{'SlotTypes':[{'ValueSelectionSetting':{'RegexFilter':{'Pattern':'a+'}}}]}])
    assert evaluate_lex_regex_operators(linked_design(r),r)[0]['verdict']=='FAIL'
    r=target('main','AWS::Lex::Bot',BotLocales='a+')
    assert evaluate_lex_regex_operators(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::Lex::Bot',BotLocales=[{'SlotTypes':[{'ValueSelectionSetting':{'RegexFilter':{'Pattern':'a+'}}}]}])
    assert any(f['rule_id']=='LEX_SLOT_REGEX_UNSUPPORTED_OPERATORS' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
