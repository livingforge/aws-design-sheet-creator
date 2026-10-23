"""Deterministic reporting of source states, input capabilities and unresolved values.

The optional source trace preserves the source's vocabulary. It is not proof that
an LLM extracted every source statement correctly, nor evidence of a host run.
"""
from collections import Counter
import hashlib
import json

# Transcribed from the source's own approval and review fields; never this tool's approval.
APPROVAL_STATES=('APPROVED','IN_REVIEW','DRAFT','REJECTED','UNRECOGNIZED','NOT_RECORDED','NOT_CITED','FORMULA_NOT_ADOPTED')
REVIEW_STATES=('ACCEPTED','CHANGES_REQUESTED','NOT_REVIEWED','UNRECOGNIZED','NOT_RECORDED','FORMULA_NOT_ADOPTED')


def source_review(value,states,label):
    """A transcribed approval/review record: an explicit state plus text or pointer fields only."""
    if not isinstance(value,dict) or value.get('status') not in states:raise ValueError(f'invalid {label} status')
    for key,field in value.items():
        if key=='status':continue
        if not (field is None or isinstance(field,str) or isinstance(field,list) and all(isinstance(x,str) for x in field)):
            raise ValueError(f'invalid {label} field')
    return value


def read_trace(path,document):
    """Rows, trace SHA-256 and the optional document-level approval record of the source."""
    if path is None:return [],None,None
    raw=path.read_bytes();value=json.loads(raw)
    rows=value.get('rows') if isinstance(value,dict) else value
    approval=value.get('document_approval') if isinstance(value,dict) else None
    if approval is not None:source_review(approval,APPROVAL_STATES,'document approval')
    if not isinstance(rows,list) or len(rows)>10000:raise ValueError('invalid source trace rows')
    seen=set();items={i.item_id for i in document.items}
    for row in rows:
        if not isinstance(row,dict):raise ValueError('invalid source trace record')
        sid=row.get('setting_id');snapshot=row.get('source_snapshot');bindings=row.get('item_ids')
        if not isinstance(sid,str) or not sid or sid in seen:raise ValueError('duplicate or missing source setting ID')
        seen.add(sid)
        if not isinstance(snapshot,dict) or snapshot.get('setting_id')!=sid:raise ValueError('source snapshot identity mismatch')
        if row.get('kind') not in ('CFN','APP') or snapshot.get('kind')!=row['kind']:raise ValueError('source kind mismatch')
        if any(not isinstance(snapshot.get(k),str) or not snapshot[k] for k in ('status','verification_status')):
            raise ValueError('source status must be explicit')
        if not isinstance(bindings,list) or any(not isinstance(x,str) for x in bindings) or len(bindings)!=len(set(bindings)):
            raise ValueError('invalid trace item bindings')
        if set(bindings)-items:raise ValueError('source trace refers to absent generated item')
        if row['kind']=='APP' and bindings:raise ValueError('APP source cannot be counted as an AWS setting')
        if row['kind']=='CFN' and not bindings and not row.get('exclusion_reason'):
            raise ValueError('unmapped CFN source requires an explicit exclusion reason')
        if 'item_review' in row:source_review(row['item_review'],REVIEW_STATES,'item review')
    return rows,hashlib.sha256(raw).hexdigest(),approval


def review_summary(rows,approval,traced):
    """Source approval and per-row review results, counted apart from every tool state."""
    by_item={}
    for row in rows:
        status=row.get('item_review',{}).get('status','NOT_PROVIDED')
        for key in row['item_ids']:by_item[key]='MIXED' if by_item.get(key,status)!=status else status
    return {'document_approval':approval['status'] if approval else 'NOT_CITED' if traced else 'NOT_PROVIDED',
            'document_approval_detail':approval,
            'item_review_counts':dict(sorted(Counter(r['item_review']['status'] for r in rows if 'item_review' in r).items())),
            'rows_without_item_review':sum('item_review' not in r for r in rows),
            'generated_items_by_item_review':dict(sorted(Counter(by_item.values()).items())),
            'scope':'Transcribed from the source document; not an approval by this tool or proof that the source is current.'}


def rule_review_causes(coverage):
    """RULE_REVIEW_REQUIRED split by why the ledger re-opened the type."""
    from .schema_reviews import cause
    rows=[r for r in coverage if r['kind']=='RULE_REVIEW_REQUIRED']
    distinct={(r['resource_id'],r['reason']):r for r in rows}.values()
    return {'counts':dict(sorted(Counter(cause(r['reason']) for r in rows).items())),
            'resources':{c:len({r['resource_id'] for r in distinct if cause(r['reason'])==c})
                         for c in sorted({cause(r['reason']) for r in rows})}}


def build_report(document,rows=(),trace_sha256=None,approval=None):
    from .document_v11 import SchemaSetting
    bindings=getattr(document,'external_bindings',None) or {}
    bound={(r['resource_id'],r['path']):{'BOUND':'EXTERNAL_VALUE_BOUND_LOCALLY','SHAPE_MISMATCH':'EXTERNAL_BINDING_SHAPE_MISMATCH',
                                         'REGION_MISMATCH':'EXTERNAL_BINDING_REGION_MISMATCH'}.get(r['status'],'EXTERNAL_VALUE_NOT_RESOLVED')
           for r in bindings.get('uses',[])}
    unresolved=[];references=[]
    def inspect(setting,item,path,input_pointer):
        if setting.status=='NOT_APPLICABLE' or setting.mode=='OMITTED':return
        if setting.mode=='COMPOSITE':
            def walk(value,parts,pointer):
                if isinstance(value,dict):
                    if set(value)=={'$design'}:
                        inspect(SchemaSetting.model_validate(value['$design']),item,parts,pointer+'/$design');return
                    for k,v in value.items():
                        key=str(k).replace('~','~0').replace('/','~1');walk(v,parts+'/'+key,pointer+'/'+key)
                elif isinstance(value,list):
                    for i,v in enumerate(value):walk(v,parts+'/'+str(i),pointer+'/'+str(i))
            walk(setting.value,path,input_pointer+'/value');return
        if setting.status=='DECIDED' and setting.mode=='LITERAL':return
        reason={'RESOURCE_REF':'LOGICAL_REFERENCE_PHYSICAL_VALUE_UNRESOLVED','EXTERNAL_REF':bound.get((item.resource_id,path),'EXTERNAL_VALUE_NOT_RESOLVED'),
                'SECRET_REF':'SECRET_NOT_FETCHED','EXPRESSION':'EXPRESSION_NOT_EVALUATED','DEFAULT':'DEFAULT_NOT_RESOLVED'}.get(setting.mode,'UNDECIDED_INPUT')
        if setting.mode=='EXPRESSION' and isinstance(setting.expression,dict) and 'symbol' in setting.expression:
            reason='SYMBOL_TARGET_NOT_BOUND'
        record={'item_id':item.item_id,'resource_id':item.resource_id,'path':path,'input_pointer':input_pointer,
                'status':setting.status,'mode':setting.mode,'reason_code':reason,'source_ids':list(setting.sources)}
        if setting.mode=='RESOURCE_REF':
            record['targets']=setting.ref if isinstance(setting.ref,list) else [setting.ref]
            record['target_existence_checked']=True
            record['aws_findings']=[{'rule_id':r['rule_id'],'verdict':r['verdict'],'reason':r['reason']}
                                    for r in document.evaluation.results if r['rule_id']=='REFERENCE' and
                                    r.get('resource_id')==item.resource_id and (r.get('path')==path or (r.get('path') or '').startswith(path+'/'))]
            references.append(record)
        unresolved.append(record)
    for item in document.items:
        if item.origin!='cfn_only':inspect(item.expected,item,'/properties/'+item.name,item.input_pointer)
    mapped={key for row in rows for key in row['item_ids']}
    expected={i.item_id for i in document.items if i.origin!='cfn_only'}
    source_records=[{'setting_id':r['setting_id'],'kind':r['kind'],'status':r['source_snapshot']['status'],
                     'verification_status':r['source_snapshot']['verification_status'],'item_ids':r['item_ids'],
                     'source_pointer':r.get('source_pointer',''),'exclusion_reason':r.get('exclusion_reason'),
                     **({'item_review':r['item_review']['status']} if 'item_review' in r else {})}
                    for r in rows]
    return {'report_version':'1.0','input_sha256':document.input_sha256,
        'execution':{'generation_status':document.generation_status,'evaluation_status':document.evaluation_status,
                     'aws_assessment':document.evaluation.assessment,'input_completeness':document.checklist.status,
                     'project_policy_assessment':document.project_policy.assessment,
                     'design_decision_assessment':getattr(document,'decision_trace',{}).get('assessment','NOT_CHECKED'),
                     'host_acceptance':'NOT_VERIFIED_BY_CLI','whole_design_approval':'NOT_ESTABLISHED'},
        'counts':{'source_records':len(rows),'source_kinds':dict(Counter(r['kind'] for r in rows)),
                  'resources':len(document.design.resources),'top_level_items':len(document.items)},
        'source_status_counts':dict(sorted(Counter(r['source_snapshot']['status'] for r in rows).items())),
        'source_verification_counts':dict(sorted(Counter(r['source_snapshot']['verification_status'] for r in rows).items())),
        'normalized_status_counts':dict(sorted(Counter(i.expected.status for i in document.items).items())),
        'source_review':review_summary(rows,approval,trace_sha256 is not None),
        'trace':{'status':'NOT_PROVIDED' if trace_sha256 is None else 'COMPLETE_FOR_GENERATED_INPUTS' if mapped==expected else 'PARTIAL',
                 'sha256':trace_sha256,'unmapped_item_ids':sorted(expected-mapped),
                 'validation_scope':'Source IDs, explicit states, kind and generated-item bindings only; source fidelity needs independent audit.'},
        'capabilities':{'RESOURCE_REF':{'supported':True,'physical_values_resolved':False},
                        'regional_catalogs':getattr(document,'regional_catalog_provenance',{}),
                        'dependency_check':'EXPLICIT_LOGICAL_GRAPH_ONLY','stack_or_deployment_order_verified':False,
                        'prose_source_extraction_verified':False,'APP_AWS_EVALUATION':False},
        'unresolved_reason_counts':dict(sorted(Counter(r['reason_code'] for r in unresolved).items())),
        'unresolved':unresolved,'internal_references':references,'source_records':source_records,
        'aws_verdicts':document.evaluation.summary.get('verdicts',{}),
        'evaluation_stages':document.evaluation.stages,
        'unchecked_reason_counts':dict(sorted(Counter(r['kind'] for r in document.evaluation.coverage).items())),
        'rule_review_causes':rule_review_causes(document.evaluation.coverage),
        'external_bindings':{'status':bindings.get('status','NOT_PROVIDED'),'sha256':bindings.get('sha256'),
                             'counts':bindings.get('counts',{}),'unused_refs':bindings.get('unused_refs',[]),
                             'scope':'Local values only; existence, ownership and current state in AWS are not verified.'},
        'interpretation_notes':[
            '元資料の状態と、構造化入力のDECIDED/UNDECIDEDは別の集計です。架空決定を実承認へ読み替えません。',
            'RESOURCE_REFは対応済みです。SYMBOL_TARGET_NOT_BOUNDは入力内で資源IDへの対応付けがないことを示し、形式未対応を意味しません。',
            '原資料のNOT_RUNは保持します。ローカルCLI成功と実ホスト経路の成功は別の証拠が必要です。',
            '原資料の承認・レビュー結果は原本の記載の転記です。本ツールの承認ではなく、記載がない項目を承認済みと扱いません。',
            'RULE_REVIEW_REQUIREDは、地域適用性・スキーマ変更・既存の未解決事項に原因を分けて数えます。',
            '外部参照のバインディング値は利用者が与えた値です。型だけを検査し、AWS上の実在・所有・現在の状態は確認しません。',
            '未登録要件、未検査、未決定、APPの業務妥当性をPASSと扱いません。']}


def render_report(report):
    def counts(value):return '、'.join(f'{k}: {v}' for k,v in value.items()) or '記録なし'
    state=report['execution']
    return '\n\n'.join([
        f"生成: {state['generation_status']}。AWS評価実行: {state['evaluation_status']}、評価: {state['aws_assessment']}。",
        f"原資料 {report['counts']['source_records']}件の状態: {counts(report['source_status_counts'])}。",
        f"原資料の検証状態: {counts(report['source_verification_counts'])}。",
        f"原資料の承認: {report['source_review']['document_approval']}。項目のレビュー結果: {counts(report['source_review']['item_review_counts'])}。",
        f"構造化入力の上位項目: {counts(report['normalized_status_counts'])}。原資料行数とは異なる単位です。",
        f"AWS判定: {counts(report['aws_verdicts'])}。",
        f"未解決理由: {counts(report['unresolved_reason_counts'])}。",
        f"要確認ルールの原因（未検査の件数）: {counts(report['rule_review_causes']['counts'])}。",
        f"外部参照のバインディング: {report['external_bindings']['status']}（{counts(report['external_bindings']['counts'])}）。",
        *report['interpretation_notes'],
        '実ホストの受入: NOT_VERIFIED_BY_CLI。設計全体の承認: NOT_ESTABLISHED。'])+'\n'
