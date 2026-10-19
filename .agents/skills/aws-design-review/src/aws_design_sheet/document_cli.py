"""Generate a document and inspect required inputs locally; not AWS design approval."""
import argparse
import json
from pathlib import Path

from pydantic import ValidationError

from .document_model import DocumentInput, Document
from .document_normalize import InputError, normalize
from .document_workbook import workbook
from .document_policy_model import PolicyConfigurationError
from .schema_bootstrap import SchemaSetupError, resolve_schema_dir


def generate(input_path,environment,output,cfn_path=None,volume_size=10,*,evaluate_design=False,source_trace=None):
    resolve_schema_dir(Path(__file__).resolve().parents[2] / 'schemas')
    if output.exists():raise InputError('output directory already exists; use a fresh destination')
    raw=input_path.read_bytes();cfn_raw=cfn_path.read_bytes() if cfn_path else None
    document=normalize(raw,environment,cfn_raw)
    if not 1<=volume_size<=50:raise InputError('volume size must be 1..50')
    if evaluate_design:
        from .document_evaluation import evaluate
        document.evaluation=evaluate(document)
        document.evaluation_status=document.evaluation.status
    report_rows=[]
    if document.model_version=='1.1':
        from .document_report import read_trace,build_report
        report_rows,trace_hash=read_trace(source_trace,document)
        document.review_report=build_report(document,report_rows,trace_hash)
    elif source_trace is not None:raise InputError('source trace requires schema version 1.1')
    book=workbook(document,services=set()) if document.model_version=='1.1' else workbook(document)
    output.mkdir(parents=True)
    book.save(output/'design.xlsx')
    volumes=[]
    if document.model_version=='1.1':
        services=sorted(set(document.resource_services.values()))
        for offset in range(0,len(services),volume_size):
            selected=services[offset:offset+volume_size];name=f'services-{offset//volume_size+1:02d}.xlsx'
            part=workbook(document,services=selected,service_only=True);part.save(output/name);part.close()
            volumes.append({'file':name,'services':selected,'item_ids':[i.item_id for i in document.items if i.service in selected]})
        (output/'volumes.json').write_text(json.dumps(volumes,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
        index=book.create_sheet('分冊一覧');index.append(['ファイル','サービス','設定数'])
        for volume in volumes:
            index.append([volume['file'],', '.join(volume['services']),len(volume['item_ids'])])
            index.cell(index.max_row,1).hyperlink=volume['file']
        index.freeze_panes='A2';index.auto_filter.ref=index.dimensions
        for column,width in [('A',25),('B',100),('C',14)]:index.column_dimensions[column].width=width
        index.print_title_rows='1:1';index.sheet_properties.pageSetUpPr.fitToPage=True
        index.page_setup.orientation='landscape';index.page_setup.paperSize=index.PAPERSIZE_A3
        index.page_setup.fitToWidth=1;index.page_setup.fitToHeight=0
        book.save(output/'design.xlsx')
    book.close()
    (output/'design.json').write_text(document.model_dump_json(indent=2)+'\n',encoding='utf8')
    (output/'checklist.json').write_text(document.checklist.model_dump_json(indent=2)+'\n',encoding='utf8')
    if document.design.project_policies:
        (output/'project-policy.json').write_text(document.project_policy.model_dump_json(indent=2)+'\n',encoding='utf8')
    summary={'generation_status':'GENERATED','evaluation_status':document.evaluation_status,'environment':environment,
             'resources':len(document.design.resources),'items':len(document.items),
             'differences':sum(x.comparison=='DIFFERENT' for x in document.items),
             'unresolved':sum(x.comparison=='UNRESOLVED' for x in document.items),
             'undecided':sum(x.expected.status=='UNDECIDED' for x in document.items),
             'input_completeness':document.checklist.status,'checklist':document.checklist.summary}
    summary.update(project_policy_status=document.project_policy.status,
                   project_policy_assessment=document.project_policy.assessment,
                   project_policy=document.project_policy.summary)
    if evaluate_design:
        (output/'evaluation.json').write_text(document.evaluation.model_dump_json(indent=2)+'\n',encoding='utf8')
        summary.update(aws_assessment=document.evaluation.assessment,evaluation=document.evaluation.summary,
                       evaluation_stages={k:v['status'] for k,v in document.evaluation.stages.items()})
    if document.model_version=='1.1':
        trace=document.decision_trace
        summary.update(design_decision_status=trace['status'],design_decision_assessment=trace['assessment'],
                       design_decisions=trace['summary'],basic_design_file='basic-design.md')
        if trace['status']!='NOT_CHECKED':summary['decision_trace_file']='decision-trace.json'
    if document.model_version=='1.1':summary.update(services=len(set(document.resource_services.values())),volumes=volumes,catalog=document.catalog_provenance,
        review_report_file='review-report.json',regional_catalogs=document.regional_catalog_provenance,
        literal_matches=sum(x.comparison=='MATCH' for x in document.items),
        expression_matches=sum(x.comparison=='EXPRESSION_MATCH' for x in document.items),
        unresolved_values=sum(x.expected_resolution in ('UNRESOLVED','PARTIAL') for x in document.items))
    (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf8')
    if document.model_version=='1.1':
        from .document_report import render_report
        (output/'review-report.json').write_text(json.dumps(document.review_report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        (output/'review-report.md').write_text(render_report(document.review_report),encoding='utf-8')
        from .document_decisions import render_basic_design
        (output/'basic-design.md').write_text(render_basic_design(document),encoding='utf-8')
        if document.decision_trace['status']!='NOT_CHECKED':
            (output/'decision-trace.json').write_text(json.dumps(document.decision_trace,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        if source_trace is not None:(output/'source-trace.json').write_text(json.dumps(report_rows,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return summary


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',type=Path,nargs='?');p.add_argument('--environment');p.add_argument('--cfn',type=Path)
    p.add_argument('--output',type=Path);p.add_argument('--schema',choices=['input','normalized'])
    p.add_argument('--schema-version',choices=['1.0','1.1'],default='1.0');p.add_argument('--volume-size',type=int,default=10)
    p.add_argument('--evaluate',action='store_true',help='run the local checker and cfn-lint on effective design inputs')
    p.add_argument('--source-trace',type=Path,help='optional original source states and bindings; never implies source fidelity or host acceptance')
    a=p.parse_args(argv)
    if a.schema:
        if a.schema_version=='1.1':
            from .document_v11 import SchemaInput,SchemaDocument
            model=SchemaInput if a.schema=='input' else SchemaDocument
        else:model=DocumentInput if a.schema=='input' else Document
        print(json.dumps(model.model_json_schema(),ensure_ascii=False,indent=2));return 0
    if not a.input or not a.environment or not a.output:p.error('input, --environment and --output are required')
    try:
        result=generate(a.input,a.environment,a.output,a.cfn,a.volume_size,evaluate_design=a.evaluate,source_trace=a.source_trace)
    except SchemaSetupError as exc:
        print(json.dumps({'generation_status':'SCHEMA_SETUP_REQUIRED','message':str(exc)}));return 2
    except PolicyConfigurationError as exc:
        print(json.dumps({'generation_status':'POLICY_CONFIGURATION_ERROR','error_code':exc.code}));return 2
    except ValidationError as exc:
        policy_error=any(e['loc'] and e['loc'][0] in ('project_policies','policy_exceptions') for e in exc.errors(include_input=False,include_context=False))
        print(json.dumps({'generation_status':'POLICY_CONFIGURATION_ERROR' if policy_error else 'STRUCTURE_ERROR','error_count':exc.error_count(),
                          'error_types':sorted({e['type'] for e in exc.errors(include_input=False,include_context=False)})}));return 2
    except (InputError,OSError,ValueError,RecursionError):
        # No exception repr, raw source, parser excerpt or secret payload is logged.
        print(json.dumps({'generation_status':'STRUCTURE_ERROR','message':'Input or output validation failed; no source values logged.'}));return 2
    print(json.dumps(result));return 3 if result['evaluation_status'] in ('FAILED','SKIPPED') or result['project_policy_status']=='FAILED' else 0


if __name__=='__main__':raise SystemExit(main())
