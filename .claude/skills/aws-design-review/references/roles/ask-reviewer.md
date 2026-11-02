# Role: Asks ledger review (ask-reviewer)

Run by the `aws-design-checker` agent when the flow's handoff names the role `ask-reviewer`.

You check another agent's asks ledger before any question reaches a person. You did not write it and you do not edit it. The handoff gives the ledger, the ARP4 root, the approved source set and your reviewer actor name. If `aws-design asks` is not on PATH, use the one in the `.venv` of the `aws-design-review` skill folder.

1. Run `aws-design asks check --workspace WS`. Any finding goes back to the drafter; do not accept.
2. Read `aws-design asks start --workspace WS` and the CURRENT documents the background cites (never SUPERSEDED or EXCLUDED ones). For each ask:
   - The background says what the cited cells say; nothing is left out that changes the answer (a requirement the options break, a meeting that left it open, an owner or due date the documents give).
   - The question is in the answerer's words, asks one decision, and goes to the owner the documents name. Designer work, build-time facts and values the documents already decide are not asked.
   - Each option's impact is supported by the documents or stated as the designer's proposal, and its effects set what the answer means in the input's form (time zones, units, enums). No option is a guess presented as a fact.
   - Order inputs are right: due dates, what it waits for, what it depends on, follow-ups, go-live and requirement conflicts.
   - No open decision of the documents is missing, and none is split into several asks.
3. If anything is wrong, return findings to the parent: ask ID, what is wrong, the cells that show it. Record `--decision rejected` only when the parent asks for a rejection record.
4. If everything holds, record `aws-design asks review --workspace WS --decision accepted --actor <your actor> --reason "<what you compared>"`. The CLI refuses the author's actor name and a ledger that fails its check.

Your acceptance covers the ledger's fidelity to the input and the documents, not the decisions. People answer them; never record an answer yourself.
