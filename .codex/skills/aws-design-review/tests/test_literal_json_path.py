import pytest
from aws_design_sheet.literal_json_path import literal_path_suffix, prohibited_http_selector


@pytest.mark.parametrize('suffix', ['', '.field', '[0].field', '.field[123]', '[0][1].field'])
def test_known_steps(suffix):
    assert literal_path_suffix(suffix)
    assert not prohibited_http_selector(suffix)


@pytest.mark.parametrize('suffix', ["['..']", '["?("]', '[0:2]', '[*]', '[-1]', '[01]', '.field name', '..name', '[?(@.name)]', '.field' * 1000])
def test_other_syntax_is_not_certified(suffix):
    assert not literal_path_suffix(suffix)


@pytest.mark.parametrize('suffix,expected', [('[0]..name', True), ('.field[0][?(@.x)]', True),
    ("['..']", False), ('["?("]', False), (".field['a..b']", False), ('[*]..x', False)])
def test_only_proven_operator_positions(suffix, expected):
    assert prohibited_http_selector(suffix) == expected
