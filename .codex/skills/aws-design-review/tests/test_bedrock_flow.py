import json
from pathlib import Path
import pytest
from aws_design_sheet.checks.bedrock.flow import evaluate_bedrock_flow, condition_names
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('expression,names',[
 ('profit > expenses',{'profit','expenses'}),('(A < B) and (C == 1)',{'A','B','C'}),
 ('not (profit <= -10)',{'profit'}),('"profit" == "profit"',set()),
 ('enabled == true',{'enabled'}),('A >= 0 or B != "A"',{'A','B'}),
 ('A.contains("x")',None),('A[0] == 1',None),('A + 1 > 2',None),('A >',None),('${A} > 0',None)])
def test_expression_parser(expression,names):assert condition_names(expression)==names


def encoded_keys(value):
    if isinstance(value,dict):return {k[0].lower()+k[1:]:encoded_keys(v) for k,v in value.items()}
    if isinstance(value,list):return [encoded_keys(v) for v in value]
    return value


def make(nodes,mode):
    definition={'Nodes':nodes}
    if mode=='nested':definition={'Nodes':[{'Type':'Loop','Configuration':{'Loop':{'Definition':definition}}}]}
    return target('main','AWS::Bedrock::Flow',**({'DefinitionString':json.dumps(encoded_keys(definition))} if mode=='string' else {'Definition':definition}))


@pytest.mark.parametrize('mode',['nested','string'])
@pytest.mark.parametrize('case',['valid','wrong_config','missing_config','input_ports','output_ports','unknown_config','unknown_type'])
def test_nested_constraints(mode,case):
    node={'Name':'node','Type':'Input','Configuration':{'Input':{}}}
    if case=='wrong_config':node['Configuration']={'Output':{}}
    if case=='missing_config':node.pop('Configuration')
    if case=='input_ports':node['Inputs']=[]
    if case=='output_ports':node.update(Type='Output',Configuration={'Output':{}},Outputs=[])
    if case=='unknown_config':node['Configuration']=UNKNOWN
    if case=='unknown_type':node['Type']=UNKNOWN
    r=make([node],mode);rows=evaluate_bedrock_flow(linked_design(r),r)
    assert rows[-1]['verdict']==('PASS' if case=='valid' else 'NOT_APPLICABLE' if case=='missing_config' else 'NEEDS_REVIEW' if case in ('unknown_config','unknown_type') else 'FAIL')
    assert '/DefinitionString/' in rows[-1]['path'] if mode=='string' else '/Loop/Definition/' in rows[-1]['path']


@pytest.mark.parametrize('mode',['direct','nested','string'])
@pytest.mark.parametrize('case',['valid','quoted_only','unknown_input','duplicate_input','unknown_expression','unsupported','default'])
def test_conditions(mode,case):
    expr='profit > 0' if case=='valid' else '"profit" == "profit"' if case=='quoted_only' else UNKNOWN if case=='unknown_expression' else 'profit[0] == 1' if case=='unsupported' else 'profit > 0'
    inputs=[{'Name':UNKNOWN if case=='unknown_input' else 'profit'}]
    if case=='duplicate_input':inputs*=2
    conditions=[{'Name':'branch',**({} if case=='default' else {'Expression':expr})}]
    r=make([{'Type':'Condition','Inputs':inputs,'Configuration':{'Condition':{'Conditions':conditions}}}],mode)
    rows=[f for f in evaluate_bedrock_flow(linked_design(r),r) if f['rule_id']=='BEDROCK_FLOW_CONDITION_INPUT_REFERENCE']
    if case=='default':assert rows==[]
    else:assert rows[0]['verdict']==('PASS' if case=='valid' else 'FAIL' if case=='quoted_only' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('case',['duplicates','substitution','uppercase','broken','s3','ambiguous','deep','wide'])
def test_definition_limits(case):
    props={'DefinitionString':'{"nodes":[],"nodes":[]}'} if case=='duplicates' else {'DefinitionString':'{"nodes":[]}', 'DefinitionSubstitutions':{'x':'value'}} if case=='substitution' else {'DefinitionString':'{"Nodes":[]}'} if case=='uppercase' else {'DefinitionString':'not JSON'} if case=='broken' else {'DefinitionS3Location':{'Bucket':'example','Key':'flow'}} if case=='s3' else {'Definition':{'Nodes':[]},'DefinitionString':'{"nodes":[]}'}
    if case in ('deep','wide'):
        d={'Nodes':[{'Type':'Input','Configuration':{'Input':{}}}]*1001} if case=='wide' else {'Nodes':[]}
        if case=='deep':
            for _ in range(18):d={'Nodes':[{'Type':'Loop','Configuration':{'Loop':{'Definition':d}}}]}
        props={'Definition':d}
    r=target('main','AWS::Bedrock::Flow',**props)
    assert any(f['verdict']=='NEEDS_REVIEW' for f in evaluate_bedrock_flow(linked_design(r),r))


def test_checker_evidence():
    r=make([{'Type':'Output','Configuration':{'Input':{}}}],'string')
    root=Path(__file__).resolve().parents[1]
    rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    finding=next(f for f in rows if f['rule_id']=='BEDROCK_FLOW_NESTED_NODE_CONSTRAINTS')
    assert finding['verdict']=='FAIL' and finding['evidence_ids']
