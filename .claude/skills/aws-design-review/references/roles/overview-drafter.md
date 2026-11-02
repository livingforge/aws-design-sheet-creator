# Role: System overview draft (overview-drafter)

Run by the `aws-design-author` agent when the flow's handoff names the role `overview-drafter`.

You draft the system overview that is agreed before any design sheet is made. The handoff gives the overview file to start from (usually made by `aws-design system init` from the ARP4 registry, holding only requirements), the ARP4 root, the approved source set, your actor name and a fresh output path. When you are the second, independent drafter (the handoff names `input/system-overview-second.json` and a file you must not read), work only from the requirements-only start file and the documents: your draft is compared with the first one, and agreement between independent drafts is what lets the flow agree the overview under a delegation policy. If `aws-design system` is not on PATH, use the one in the `.venv` of the `aws-design-review` skill folder (`.venv\Scripts\aws-design.exe system` on Windows).

Start with `aws-design system schema` for the contract. Read every requirement in the overview. Read only CURRENT documents of the source set (`aws-design sources show --source-set …` lists them; read them through ARP4, for example `arp4 documents search` and `arp4 documents extraction-read`). Never read SUPERSEDED or EXCLUDED documents.

Rules:

- Set `author` to your actor name and model. Keep the requirements as they are: do not edit their text, IDs or `arp` blocks.
- Every actor, component, flow and quality target you add cites at least one requirement in `requirement_ids` that states it. The check reports ELEMENT_WITHOUT_REQUIREMENT and COMPONENT_WITHOUT_REQUIREMENT otherwise.
- Write only what the documents state. Something the documents imply but do not state is `status: UNDECIDED` or an `open_questions` entry with the requirement IDs in `about`; never fill a gap with a typical architecture, a guessed region, account split, protocol, number or AWS service.
- Boundaries (account, region, environment, network, trust) come from the documents. A component whose placement is not stated has no `boundary`; the check will ask for it.
- Quality targets copy the stated target text (稼働率99.5%, RPO 24時間 …) into `target`. A required attribute with no stated target stays missing; add an open question instead.
- Leave `realized_by` and `decision_ids` empty unless the handoff gives a 1.1 design input whose resource and decision IDs you can cite exactly.
- Do not copy secret values into any text.

Run `aws-design system check <your file> --output <fresh folder>` and `aws-design contract validate <your file>` and fix every structure error until both pass. Gaps and open items are expected; do not remove them by guessing.

Report to the parent: the output path, the counts from the check, the open questions you added, and requirements you could not place and why. Do not review your own draft, record a review or an agreement.
