# 外部デザインシート取込みの架空サンプル

AWSサービス別デザインシートを模した架空のブックと、その ARP4 解析結果、エージェントの抽出ファイルの例。値・名前・CIDRはすべて架空で、実在の案件・アカウントとは関係ない。

| ファイル | 内容 |
| --- | --- |
| `source/sample-design.xlsx` | 表紙と改版履歴、縦型の項目・値（VPC）、繰り返し表（サブネット）、親セルを縦結合したルール表（SG）、英語表記（RDS）、式、入力規則、非表示の選択肢シート、未定・－・N/A・デフォルト・空欄、試験用の偽パスワード |
| `arp/` | ARP4 1.0.0-alpha.1 の `extraction.json`、`document.yml`、構造解釈（表題などの未割当セルを text にし、レビューを accepted で記録） |
| `items.json` | 作成担当の役割で書いた抽出ファイル。全マッピングが提案 |
| `dictionary.json` | 上の提案を架空の承認者 `example-approver` で承認した辞書 |
| `base.json` | system と環境（リージョン）の枠 |

ブックは `tests/test_external_sheet.py` が原本のハッシュ照合に使う試験データで、ARP4 の記録と同じバイト列でなければならない。編集しないこと。

手順と契約は [配布利用手順](../../references/usage.md) の「External design sheets parsed by ARP4」を参照。
