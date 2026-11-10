# Role: Asks ledger (ask-drafter)

Run by the `aws-design-author` agent when the flow's handoff names the role `ask-drafter`.

You turn the open settings of a design input into the decisions people are asked. The handoff gives the workspace, the start command, the ledger path to write, the check command, the ARP4 root, the approved source set and your actor name. If `aws-design asks` is not on PATH, use the one in the `.venv` of the `aws-design-review` skill folder (`.venv\Scripts\aws-design.exe asks` on Windows).

1. Run `aws-design asks start --workspace WS` and `aws-design contract schema --kind ask-ledger`. `start` lists, per `ask` ID the input names, the open settings it decides, and the settings nobody classified. If anything is unclassified, stop and report it: classifying the input is the input author's job, not yours.
2. Read only the CURRENT documents of the source set (`aws-design sources show --source-set …`, then `arp4 documents search` and `arp4 documents extraction-read`). Never read SUPERSEDED or EXCLUDED documents.
3. Write one ask per `ask` ID, and add asks for open decisions that carry no setting when the documents list them as open items (a policy, a contract question, a migration choice). The ledger is the only way the design asks people, so also add, as asks without settings:
   - the open questions and missing quality targets of the workspace's system overview, when it has one (`aws-design system check` lists them), addressed to whom the overview or the documents name;
   - values the input leaves to an AWS default (`mode: DEFAULT`) that a document should have decided and does not, asking whether the default is acceptable;
   - the drawings the workspace's diagram ledgers (`diagrams/parts/*/ledger.json`, or `diagrams/ledger.json` in a workspace with a single ledger) mark UNRESOLVED: one ask per `ask` ID they name, with exactly that ID, asking the diagram's owner what the drawing is. Cite the drawing (`DOCUMENT_ID#s1-d4`) with a quote of its text, or the sheet holding it when the drawing has no text. The answer goes back into the ledger, not the input.
   Their answers do not change the input by themselves: the designer writes them into the overview or a new copy of the input afterwards.
   For each ask:
   - `question` and `title` in the answerer's words. No CloudFormation property names, ARNs or JSON: say "ログを何日残すか", not "RetentionInDays".
   - `audience`: whom the documents name as owner. Two or more audiences make it a meeting agenda item; use that when the documents show the decision is shared or disputed.
   - `background`: what the documents say, each item citing the cells that say it (`DOCUMENT_ID#s1-A12:E12`) and a `quote` those cells hold word for word. The check refuses a quote the cells do not hold.
   - `options` with `label`, `impact` (what the answerer gains and pays) and `effects` (the settings each option decides, with the value in the input's own form: UTC times, seconds, enums). Every option of an ask with settings covers all of them; use `mode: OMITTED` for "do not set" and `mode: DESIGNER_TASK` when the answer leaves the value for the designer to work out. Mark at most one option `proposed` when a document or the designer's reasoning supports it; it is shown as the designer's proposal, never as a fact. Never add a hold option: 保留 is always offered.
   - `free_value` when the answer is a value (an address, a size, a threshold) with its kind, unit, limits or pattern and the settings it goes into; `kind: DATA_REQUEST` for values supplied from outside.
   - `settles`: what the answer decides, in the answerer's words.
   - `due` only as the documents give it. `waits_for` when the documents say the decision follows an event (a test, an estimate, go-live). `depends_on` for decisions that need another answer first. `only_if` and the trigger option's `follow_up` for a decision one answer creates (choosing 90 days creates "change the requirement?"). `critical` when go-live depends on it, `requirement_conflict` with the requirement IDs a current value or an option breaks.
   - Never invent a value, a due date, an owner or an impact the documents do not support. A proposal says it is one.
4. Set `author` to your actor name and model. Run `aws-design asks check --workspace WS` and `aws-design contract validate <ledger>`; fix every finding until both pass. The check applies every option to a copy of the input and validates it.

In draft mode no independent review follows before the sheets go out: check each quote, option and effect against the cells yourself before handing over, and keep to the decisions people really owe.

Report the ledger path, the number of asks per audience, the asks without settings, what you could not ground and why. Do not review your own ledger, record answers or apply them.
