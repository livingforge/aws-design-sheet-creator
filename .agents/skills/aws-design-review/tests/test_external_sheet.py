"""External design sheets parsed by ARP4: agent-cited cells to 1.1 input."""
import copy
import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aws_design_sheet.external_sheet import (Dictionary, InputError, ItemsFile, Sheetbook, approve, build, check,
                                             check_report, main)

ROOT = Path(__file__).resolve().parents[1] / 'examples' / 'external-sheet'
ARP = ROOT / 'arp'
CANARY = b'Canary-Pa55w0rd-7f3e9b'
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


def sheetbook(extraction=None):
    return Sheetbook(extraction or (ARP / 'extraction.json').read_bytes(), (ARP / 'structure.yml').read_bytes(),
                     (ARP / 'document.yml').read_bytes())


def fixture_items():
    return json.loads((ROOT / 'items.json').read_text(encoding='utf-8'))


def raw(value):return json.dumps(value, ensure_ascii=False).encode('utf-8')


def item(data, item_id):return next(i for i in data['items'] if i['id'] == item_id)


def codes(data, dictionary=None):
    result = check(sheetbook(), ItemsFile.model_validate(data), dictionary or Dictionary(schema_version='1'))
    return {e['code'] for e in result.errors}


def approved(data, approver='example-approver'):
    dictionary, _ = approve(sheetbook(), ItemsFile.model_validate(data), Dictionary(schema_version='1'), approver, now=NOW)
    return dictionary


def review_for(items_raw, decision='accepted'):
    return raw({'schema_version': '1', 'items_sha256': hashlib.sha256(items_raw).hexdigest(), 'decision': decision,
                'actor': 'fixture-reviewer', 'reason': 'checked', 'recorded_at': '2026-10-19T00:00:00Z'})


def run(data=None, dictionary=None, review=True, **kwargs):
    data = data or fixture_items();items_raw = raw(data)
    dictionary = approved(data) if dictionary is None else dictionary
    return build(sheetbook(), items_raw, raw(dictionary.model_dump(exclude_none=True)), (ROOT / 'base.json').read_bytes(),
                 review_raw=review_for(items_raw) if review else None, **kwargs)


def test_fixture_items_pass_and_account_for_every_cell():
    result = check(sheetbook(), ItemsFile.model_validate(fixture_items()), Dictionary(schema_version='1'))
    assert check_report(result)['status'] == 'PASS', result.errors
    assert set(sheetbook().nonempty()) <= set(result.referenced) | result.header_covered


def test_dropping_a_retained_item_leaves_its_cells_uncovered():
    data = fixture_items()
    data['extensions'] = [e for e in data['extensions'] if e['id'] != 'ops.incident-contact']
    result = check(sheetbook(), ItemsFile.model_validate(data), Dictionary(schema_version='1'))
    uncovered = next(e for e in result.errors if e['code'] == 'UNCOVERED_CELLS')
    assert uncovered['cells'] == ['s5-B5', 's5-C5']


@pytest.mark.parametrize('item_id,change,code', [
    ('db.max-allocated-storage', {'state': 'LITERAL'}, 'FORMULA_AS_LITERAL'),
    ('db.maintenance-window', {'state': 'LITERAL'}, 'EMPTY_VALUE_CELL'),
    ('db.maintenance-window', {'state': 'UNDECIDED'}, 'EMPTY_VALUE_CELL'),
    ('db.engine', {'state': 'BLANK'}, 'NOT_BLANK'),
    ('db.engine', {'state': 'FORMULA'}, 'NOT_A_FORMULA'),
    ('db.engine', {'state': 'UNDECIDED'}, 'STATE_WORD_UNKNOWN'),
    ('vpc.instance-tenancy', {'state': 'UNDECIDED'}, 'STATE_WORD_UNKNOWN'),
    ('db-sg.ingress-0.source', {'ref': 'db-sg'}, 'REF_NAME_MISMATCH'),
    ('db.master-password', {'state': 'LITERAL'}, 'SENSITIVE_PATH_NEEDS_SECRET_STATE'),
    ('db.master-password', {'state': 'SECRET_REF'}, 'NOT_A_SECRET_REFERENCE'),
    ('web-sg.ingress-0.port', {'value_cell': 's3-F5'}, 'VALUE_CELL_REUSED'),
    ('web-sg.ingress-1.port', {'paths': ['/SecurityGroupIngress/5/FromPort', '/SecurityGroupIngress/5/ToPort']}, 'ARRAY_GAP'),
    ('vpc.cidr-block', {'paths': ['/Ipv6CidrBlock']}, 'INVALID_PATH'),
    ('vpc.cidr-block', {'paths': ['/EnableDnsSupport']}, 'PATH_CONFLICT'),
    ('vpc.enable-dns-hostnames', {'mapping': {'proposal': {'convert': 'boolean'}}}, 'VALUE_NOT_CONVERTIBLE'),
    ('db.allocated-storage', {'mapping': {'proposal': {'convert': 'integer', 'units': ['GB']}}}, 'SCHEMA_TYPE_MISMATCH'),
    ('db.backup-retention', {'mapping': {'proposal': {'convert': 'integer', 'units': ['hours']}}}, 'UNIT_MISMATCH'),
    ('web-sg.group-description', {'value_cell': 's3-C5'}, 'MERGED_NON_ANCHOR'),
    ('db.engine', {'value_cell': 's9-C5'}, 'UNKNOWN_SHEET'),
])
def test_claims_contradicting_the_extraction_are_rejected(item_id, change, code):
    data = fixture_items();item(data, item_id).update(change)
    assert code in codes(data)


def test_array_element_needs_its_required_members():
    data = fixture_items()
    data['unmapped'] = [u for u in data['unmapped'] if u['id'] != 'vpc.name-tag']
    data['unmapped'].append({'id': 'vpc.name-tag-note', 'category': 'NEEDS_CONFIRMATION', 'cells': ['s2-D10'],
                             'resources': ['vpc'], 'reason': 'note', 'follow_up': 'confirm'})
    data['items'].append({'id': 'vpc.name-tag', 'resource': 'vpc', 'label_cells': ['s2-B10'], 'value_cell': 's2-C10',
                          'paths': ['/Tags/0/Value'], 'state': 'FORMULA', 'mapping': {'proposal': {'convert': 'string'}}})
    assert codes(data) == {'INCOMPLETE_ELEMENT'}
    data = fixture_items();item(data, 'web-sg.ingress-1.protocol')['paths'] = ['/SecurityGroupIngress/1/Description']
    assert 'INCOMPLETE_ELEMENT' in codes(data)


def test_agent_text_cannot_repeat_a_secret_value():
    data = fixture_items()
    item(data, 'db.master-password')['reason'] = 'value is ' + CANARY.decode()
    assert codes(data) == {'SECRET_IN_AGENT_TEXT'}
    data = fixture_items()
    # Fictional key ID, assembled so repository secret scanners do not flag the fixture.
    data['unmapped'][0]['follow_up'] = 'key ' + 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP'
    assert codes(data) == {'SECRET_IN_AGENT_TEXT'}


def test_binding_staleness_and_unaccepted_structure():
    data = fixture_items();data['binding']['extraction_sha256'] = '0' * 64
    assert 'BINDING_EXTRACTION_MISMATCH' in codes(data)
    changed = (ARP / 'extraction.json').read_bytes().replace(b'10.20.0.0/16', b'10.21.0.0/16')
    with pytest.raises(InputError, match='STRUCTURE_STALE'):sheetbook(changed)
    pending = (ARP / 'structure.yml').read_text(encoding='utf-8').replace('status: accepted', 'status: pending')
    book = Sheetbook((ARP / 'extraction.json').read_bytes(), pending.encode('utf-8'))
    result = check(book, ItemsFile.model_validate(fixture_items()), Dictionary(schema_version='1'))
    assert {'STRUCTURE_NOT_ACCEPTED'} == {e['code'] for e in result.errors}


def test_proposals_are_not_written_until_approved():
    files, summary = run(dictionary=Dictionary(schema_version='1'))
    design = json.loads(files['input.json'])
    assert all(r['settings'] == {} for r in design['resources'])
    assert summary['outcome_counts']['PROPOSED'] == 36 and 'MAPPED' not in summary['outcome_counts']
    files, summary = run()
    assert summary['outcome_counts']['MAPPED'] == 33
    assert summary['reasons'] == ['NEEDS_CONFIRMATION:3', 'UNMAPPED:7']


def test_approval_deduplicates_and_records_the_approver():
    data = fixture_items()
    dictionary = approved(data)
    assert len(dictionary.entries) == 26
    zone = next(e for e in dictionary.entries if e.paths == ['/AvailabilityZone'])
    assert zone.labels == ['AZ'] and zone.approved_by == 'example-approver' and zone.approved_at == '2026-10-19T00:00:00Z'
    ingress = [e for e in dictionary.entries if e.paths == ['/SecurityGroupIngress/*/FromPort', '/SecurityGroupIngress/*/ToPort']]
    assert len(ingress) == 1 and ingress[0].when[0].label == '方向' and ingress[0].when[0].values == ['インバウンド']
    with pytest.raises(InputError, match='APPROVER_REQUIRED'):approved(data, approver=' ')
    again, changes = approve(sheetbook(), ItemsFile.model_validate(data), dictionary, 'someone-else', now=NOW)
    assert changes == {'added': [], 'labels_added_to': []} and again == dictionary


def test_dictionary_entries_are_checked_against_the_cited_cells():
    data = fixture_items();dictionary = approved(data)
    by_path = {tuple(e.paths): e.id for e in dictionary.entries}
    target = item(data, 'web-sg.ingress-0.cidr')
    target['mapping'] = {'entry': by_path[('/SecurityGroupIngress/*/CidrIp',)]}
    assert codes(data, dictionary) == set()
    egress = item(data, 'web-sg.egress-0.cidr')
    egress['mapping'] = {'entry': by_path[('/SecurityGroupIngress/*/CidrIp',)]}
    assert 'PATH_NOT_IN_ENTRY' in codes(data, dictionary)
    egress['paths'] = ['/SecurityGroupIngress/2/CidrIp']
    assert 'CONDITION_MISMATCH' in codes(data, dictionary)
    data = fixture_items();item(data, 'db.engine')['mapping'] = {'entry': by_path[('/EngineVersion',)]}
    item(data, 'db.engine')['paths'] = ['/EngineVersion'];item(data, 'db.engine-version')['paths'] = ['/Engine']
    assert 'LABEL_MISMATCH' in codes(data, dictionary)


def test_states_reach_the_generated_input_without_inference():
    files, _ = run()
    resources = {r['id']: r['settings'] for r in json.loads(files['input.json'])['resources']}
    assert resources['subnet-private-c']['AvailabilityZone']['status'] == 'UNDECIDED'
    assert resources['vpc']['InstanceTenancy'] == {'mode': 'DEFAULT', 'rationale': '外部シート VPC!C8', 'sources': ['xs-2']}
    assert resources['db']['StorageEncrypted']['status'] == 'NOT_APPLICABLE'
    assert resources['db']['AllocatedStorage']['value'] == '100' and resources['db']['MultiAZ']['value'] is True
    for absent in ('MasterUserPassword', 'PreferredMaintenanceWindow', 'MaxAllocatedStorage'):assert absent not in resources['db']
    assert all('VpcId' not in resources[s] for s in ('subnet-public-a', 'subnet-private-a', 'subnet-private-c'))
    egress = resources['web-sg']['SecurityGroupEgress']
    assert egress['mode'] == 'COMPOSITE' and egress['value'][0]['FromPort'] == {'$design': {'status': 'NOT_APPLICABLE'}}
    assert resources['db-sg']['SecurityGroupIngress']['value'][0]['SourceSecurityGroupId'] == {'$design': {'mode': 'RESOURCE_REF', 'ref': 'web-sg'}}
    mapping = json.loads(files['external-mapping.json'])
    formula = next(r for r in mapping['rows'] if r['item_id'] == 'db.max-allocated-storage')
    assert formula['value_cell']['formula'] == 'C8*2' and formula['outcome'] == 'NOT_WRITTEN'
    assert formula['reason_code'] == 'FORMULA_RESULT_NOT_ADOPTED' and formula['converted_value'] is None


def test_secret_value_never_reaches_any_output(tmp_path):
    files, _ = run()
    for name, data in files.items():
        assert CANARY not in data, name
        if name.endswith('.xlsx'):
            with zipfile.ZipFile(__import__('io').BytesIO(data)) as book:
                assert all(CANARY not in book.read(part) for part in book.namelist()), name
    password = next(r for r in json.loads(files['external-mapping.json'])['rows'] if r['item_id'] == 'db.master-password')
    assert password['value_cell']['text'] == '[秘密値: 記録しない]' and password['reason_code'] == 'SECRET_VALUE_NOT_COPIED'


def test_coverage_report_counts_and_versions():
    files, summary = run(source_raw_before=(ROOT / 'source' / 'sample-design.xlsx').read_bytes(),
                         source_raw_after=(ROOT / 'source' / 'sample-design.xlsx').read_bytes())
    coverage = json.loads(files['external-coverage.json'])
    assert coverage['import_status'] == 'INCOMPLETE'
    assert coverage['outcome_counts'] == {'EXCLUDED': 4, 'EXTENSION': 5, 'MAPPED': 33, 'NEEDS_CONFIRMATION': 3, 'UNMAPPED': 7}
    assert coverage['resources'] == {'vpc': 'PARTIAL', 'subnet-public-a': 'PARTIAL', 'subnet-private-a': 'PARTIAL',
                                     'subnet-private-c': 'PARTIAL', 'web-sg': 'PARTIAL', 'db-sg': 'PARTIAL', 'db': 'PARTIAL'}
    assert [u['feature'] for u in coverage['unchecked_scope']] == ['data_validations', 'defined_names', 'sheet_protection',
                                                                  'workbook_protection', 'external_links']
    versions = coverage['versions']
    assert versions['source']['state'] == 'VERIFIED_UNCHANGED' and versions['source']['sheet_version'] == '1.2'
    assert versions['arp']['parser'].startswith('arp4-rust/') and versions['items']['review'] == 'ACCEPTED'
    assert versions['schemas'][0]['region'] == 'ap-northeast-1'
    with pytest.raises(InputError, match='SOURCE_MISMATCH'):
        run(source_raw_before=b'other', source_raw_after=b'other')


def test_review_must_match_the_items_file():
    data = fixture_items();items_raw = raw(data)
    stale = review_for(items_raw)
    data['items'][0]['reason'] = 'edited after review'
    _, summary = build(sheetbook(), raw(data), raw(approved(data).model_dump(exclude_none=True)),
                       (ROOT / 'base.json').read_bytes(), review_raw=stale)
    assert summary['reasons'][0] == 'ITEMS_REVIEW_STALE'
    _, summary = run(review=False)
    assert summary['reasons'][0] == 'ITEMS_REVIEW_MISSING'


def test_rebuild_is_byte_identical_for_json_outputs():
    first, _ = run();second, _ = run()
    for name in ('input.json', 'source-trace.json', 'external-mapping.json', 'external-coverage.json'):
        assert first[name] == second[name], name


def test_existing_generator_accepts_the_input_and_trace(tmp_path):
    from aws_design_sheet.document_cli import main as document_main
    files, _ = run()
    for name in ('input.json', 'source-trace.json'):(tmp_path / name).write_bytes(files[name])
    out = tmp_path / 'generated'
    assert document_main([str(tmp_path / 'input.json'), '--environment', 'verification', '--output', str(out),
                          '--source-trace', str(tmp_path / 'source-trace.json')]) == 0
    report = json.loads((out / 'review-report.json').read_text(encoding='utf-8'))
    assert report['trace']['status'] == 'COMPLETE_FOR_GENERATED_INPUTS'
    assert report['source_status_counts']['FORMULA'] == 1 and report['source_status_counts']['SECRET_VALUE'] == 1
    checklist = json.loads((out / 'checklist.json').read_text(encoding='utf-8'))
    missing = {(r['resource_id'], r['path']) for r in checklist['rows'] if r['result'] == 'MISSING'}
    assert ('subnet-public-a', '/properties/VpcId') in missing
    assert all(CANARY not in p.read_bytes() for p in out.rglob('*') if p.is_file())


def test_cli_review_requires_an_independent_actor_and_writes_new_files(tmp_path, capsys):
    arp = ['--extraction', str(ARP / 'extraction.json'), '--structure', str(ARP / 'structure.yml'), '--document', str(ARP / 'document.yml')]
    items = ['--items', str(ROOT / 'items.json')]
    assert main(['review', *arp, *items, '--decision', 'accepted', '--actor', 'fixture-worker-claude', '--reason', 'x',
                 '--output', str(tmp_path / 'r.json')]) == 2
    assert 'REVIEWER_IS_AUTHOR' in capsys.readouterr().out
    assert main(['review', *arp, *items, '--decision', 'accepted', '--actor', 'fixture-reviewer', '--reason', 'checked',
                 '--output', str(tmp_path / 'r.json')]) == 0
    assert main(['approve', *arp, *items, '--approver', 'example-approver', '--all', '--output', str(tmp_path / 'd.json')]) == 0
    capsys.readouterr()
    assert main(['build', *arp, *items, '--dictionary', str(tmp_path / 'd.json'), '--review', str(tmp_path / 'r.json'),
                 '--base', str(ROOT / 'base.json'), '--source', str(ROOT / 'source' / 'sample-design.xlsx'),
                 '--output', str(tmp_path / 'out')]) == 3
    assert json.loads(capsys.readouterr().out)['import_status'] == 'INCOMPLETE'
    assert main(['build', *arp, *items, '--base', str(ROOT / 'base.json'), '--output', str(tmp_path / 'out')]) == 2
    assert 'already exists' in capsys.readouterr().out


def test_original_workbook_is_only_hashed():
    source = ROOT / 'source' / 'sample-design.xlsx'
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    run(source_raw_before=source.read_bytes(), source_raw_after=source.read_bytes())
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    assert before == sheetbook().source['sha256']
