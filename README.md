# AWS Design Review — Agent / Skill distribution

AWS設計書の生成、必要入力の確認、人が登録した案件方針の照合、既存Checker／cfn-lintによる静的評価を、ローカルPythonで実行する配布版です。バージョン0.2.0。

## 導入

このリポジトリを取得し、利用するホストの **aws-design-reviewフォルダーだけ** を利用者のプロジェクトへ配置してください。他のSkill・設定ファイルを上書きしないでください。

|ホスト|配置するSkill|追加Agent（任意）|
|---|---|---|
|Claude Code|`.claude/skills/aws-design-review/`|`.claude/agents/aws-design-review.md`|
|Codex|`.agents/skills/aws-design-review/`|Skillを直接指定|
|GitHub Copilot|`.github/skills/aws-design-review/`|`.github/agents/aws-design-review.agent.md`|

旧Codex版の`.codex/skills/aws-design-review`を使っている場合は、新配置へ移行してください。新旧の同名Skillを同時に登録しないでください。

この固定依存版にはPython 3.12以上（3.14.1を除く）が必要です。検証環境はWindows／Python 3.12.10です。配置後、Skillフォルダーを作業ディレクトリにしてWindows PowerShellで実行します。

```powershell
& .\scripts\install.ps1
& .\.venv\Scripts\aws-design-document.exe .\examples\project-policies\design.json --environment prod --output .\output\first-review --evaluate
```

インストールはPyPIから依存を取得します。既存の`.venv`は上書き・削除しません。配置を移動した場合も新しいコピーへインストールしてください。Linux/macOSではSkillフォルダーで`python3 -m venv .venv`、`.venv/bin/python -m pip --isolated install --index-url https://pypi.org/simple -c requirements.lock -e .`、`.venv/bin/python -m aws_design_sheet.schema_bootstrap`を実行できますが、このリリースの実行検証環境はWindowsです。

Claude Codeでは`/aws-design-review`、Codexでは`$aws-design-review`を指定し、入力ファイル、対象環境、出力先を伝えます。Copilotでは同名Skillを指定するか同梱Agentを選択してください。ホストのバージョン・組織設定・ワークスペース信頼により、Skillやコマンド実行の許可が必要です。

## スキーマの初回取得・更新

初回セットアップは**インターネット接続が必要**です。インストーラーは依存をPyPIから、CloudFormationスキーマをAWS公式の東京リージョン公開URLから取得します。AWS資格情報やアカウント操作は不要です。ZIP本体、派生した入力スキーマ、文書カタログは配布していません。

`schemas/schema-lock.json`に公式URL・リージョン・確認日時・ツール版・承認済みSHA-256・カタログ生成結果のハッシュを固定しています。今回のZIPは`f1bba9effaad133ec6e444464992fd4f00058545875a6a4fdc069b6246d24c5b`。取得後、`schemas/.cache/<SHA-256>/`にZIP、取得日時付きmanifest、実行用ルール台帳、文書カタログ、生成記録を作ります。アーカイブ内のファイルは展開しません。

```powershell
# ネットを使わず既存キャッシュを検査
& .\.venv\Scripts\aws-design-bootstrap.exe --check
# 失敗した初回取得を再試行（作成済みの仮想環境を利用）
& .\.venv\Scripts\aws-design-bootstrap.exe
```

導入済みの通常生成・必須入力・案件方針・ローカルAWS評価はオフラインで使えます。任意のLLM抽出と公式資料の追加調査は別途ネットが必要です。公式URLの中身が固定ハッシュと異なれば停止します。最新版へ黙って切り替えたり、スキーマ欠落を合格扱いしたりしません。更新はスキーマ差分・台帳・カタログ・回帰を再検証した新しい配布版を別フォルダーへ導入してください。`aws-design-schemas`による配布ルートの上書きは拒否します。

公式URLは最新版を指すため、内容変更後に同じ版を新規取得できる保証はありません。検証済みキャッシュを保持すれば、その固定版をオフラインで再実行できます。

既存キャッシュは検査して再利用し、破損や不一致があれば上書きせず停止します。失敗した取得・途中データは`schemas/.downloads/`に残ります。復旧には新しいSkillコピーを使うか、問題のキャッシュを別の場所に保存してから初回取得を再試行してください。旧キャッシュや未知のファイルを自動削除しません。

新スキーマでは全1,629タイプのうち追加23タイプを未調査、変更96タイプのうち83タイプを再確認、従来「追加ルールなし」だった13タイプを未調査に戻しています。現行スキーマで根拠を再現できない1ルール・5参照は実行用カタログから除外し、再確認事項を残しました。50サービス文書カタログは587タイプ・3,905書込可能な最上位プロパティを含みます。これらはAWS全条件の評価済み件数ではありません。

## 使い分け

|目的|入力とコマンド|読む結果|
|---|---|---|
|設計書作成・必要入力確認|生成入力1.0／1.1 → `aws-design-document`|`design.xlsx`、`checklist.json`、`input_completeness`|
|案件方針の照合|同じ入力へ`project_policies`を明示|`project-policy.json`、`project_policy_assessment`|
|AWS静的評価|上記に`--evaluate`を追加|`evaluation.json`、`aws_assessment`|
|CFNとの記載比較|上記に`--cfn <file>`を追加|比較結果。CFNから不足値は補わない|
|既存の行形式設計テキスト検査|`aws-design-run`|中間JSON・検査JSON|
|既存の中間JSON再検査|`aws-design-check`|検査JSON|

生成用JSONと検査器用の中間JSONは別契約です。自由文・Office・PDFをそのまま生成CLIへ渡さないでください。詳細は各Skill内の`references/usage.md`を参照してください。

## 範囲とデータ

実行完了・CFN一致・入力充足・案件適合・AWS指摘は別の結果です。未知値や未登録要件を合格にせず、全体の妥当性やデプロイ成功は保証しません。AWS認証、実環境変更、秘密参照先の取得は基本機能には不要です。案件宣言は人が出典と条件を登録し、原文から自動推定しません。

秘密値は入力せず、秘密参照を利用してください。出力には利用者の設計値や出典が含まれるため、出力先の共有範囲を利用者が管理してください。任意のLLM抽出は`install.ps1 -Llm`とAnthropic認証を別途必要とし、入力を外部APIへ送信します。既定では利用しません。

同梱するのは実行ソース、ルール・プロファイル、公式スキーマ取得用の固定ハッシュ、小さな架空の使用例、126件の関連テスト、導入手順です。開発Git履歴、開発全テスト、巨大な評価証跡、大学案件の全資料、Library記録、Officeファイル、キャッシュ、認証情報は含めません。3ホストのSkill内容は同一で、`release-manifest.json`にファイルハッシュを記録しています。

テストする場合は新しいコピーへ`install.ps1 -Tests`で導入し、そのSkillフォルダーで`.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider`を実行します。生成は毎回新しい出力先を指定してください。

## ライセンス・出典

プロジェクトのコードは[MIT](LICENSE)です。第三者資材はプロジェクトのMITへ読み替えず、[出典とライセンス案内](THIRD_PARTY_NOTICES.md)を参照してください。

ホスト配置の確認元：[Claude Code](https://code.claude.com/docs/en/skills)、[Codex](https://learn.chatgpt.com/docs/build-skills)、[GitHub Copilot](https://docs.github.com/en/copilot/concepts/agents/about-agent-skills)。確認日：2026-10-13。
