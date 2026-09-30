# AWS Design Sheet Creator

AWS の設計情報を UTF-8 テキストから抽出し、固定した CloudFormation スキーマと設計ルールで検査するローカルツール。検査結果と根拠、未検査範囲を JSON に保存し、Excel レポートも作成できる。Codex、Claude、GitHub Copilot 向けの Agent／Skill を同梱する。

## 導入（Windows）

Python 3.11 以上と Git を用意する。

```powershell
git clone https://github.com/livingforge/aws-design-sheet-creator.git
Set-Location aws-design-sheet-creator
& .\scripts\install.ps1
```

導入スクリプトはこのフォルダ内の `.venv` に依存パッケージをインストールする。Claude による自由文抽出を使う場合は `& .\scripts\install.ps1 -Llm` で追加依存を導入し、Anthropic API の認証情報を設定する。通常の行形式の検査には API 認証は必要ない。

## 検査する

入力は UTF-8 の行形式。例えば `VPC main: CidrBlock=10.0.0.0/16; EnableDnsSupport=false`、`Subnet private-a: Vpc=main; CidrBlock=10.0.1.0/24; AvailabilityZone=ap-northeast-1a` のように記す。正式な CloudFormation タイプ名も使える。

```powershell
& .\.venv\Scripts\aws-design-run.exe .\examples\network.txt --project sample --environment prod --account 111111111111 --intermediate .\output\design.json --result .\output\result.json
& .\.venv\Scripts\aws-design-excel.exe .\output\result.json --design .\output\design.json --output .\output\report.xlsx
```

`--region` の既定値は `ap-northeast-1`。同梱スキーマも東京リージョンの固定版なので、別リージョンを使う場合は対応するスキーマを用意する。既存の中間 JSON は `aws-design-check` で再検査できる。`status: COMPLETE` は処理完了を表す値で、各判定の `FAIL`・`NEEDS_REVIEW` や `coverage` に残る未検査範囲も確認する。検査結果は AWS へのデプロイ可否を保証しない。

## Agent／Skill

このフォルダを作業ディレクトリとして開くと、対応するホストは次の Skill を参照できる。

- Codex: `.codex/skills/aws-design-review/SKILL.md`
- Claude: `.claude/skills/aws-design-review/SKILL.md`、`.claude/agents/aws-design-review.md`
- GitHub Copilot: `.github/skills/aws-design-review/SKILL.md`、`.github/agents/aws-design-review.agent.md`

Agent／Skill はローカル CLI を実行し、結果と原文の根拠を読み取って報告する。出力は指定したパスに作成される。`output/` と `.venv/` は Git の追跡対象外。

## 同梱データ

`src/` が Python 本体、`schemas/` が固定スキーマ、`profiles/` が設計項目、`rules/` がルール・参照台帳。これらを同じフォルダ構成で保持する。インストールは編集可能形式なので、フォルダを移動した場合は `.venv` を作り直す。

この配布内容の元となった開発版コミットは `380fd4998ea0022bc6802004b57bc8a518123715`。
