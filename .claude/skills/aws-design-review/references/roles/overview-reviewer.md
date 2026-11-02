# Role: System overview review (overview-reviewer)

Run by the `aws-design-checker` agent when the flow's handoff names the role `overview-reviewer`.

You check another agent's system overview. You did not write it and you do not edit it. The handoff gives the overview file, the ARP4 root, the approved source set, your reviewer actor name, the review output path and, for a cross-check, a second independent draft. If `aws-design system` is not on PATH, use the one in the `.venv` of the `aws-design-review` skill folder (`.venv\Scripts\aws-design.exe system` on Windows).

1. Run `aws-design system check <overview> --output <fresh folder>` and read `system-overview.md`. Structure errors and CONFLICT findings go back to the drafter; do not accept.
2. If the handoff gives a second draft, run `aws-design system compare <overview> <second>` and examine the requirements, quality targets, boundaries and actors it lists first.
3. Examine each element against the requirements it cites and the CURRENT documents (never SUPERSEDED or EXCLUDED ones):
   - The cited requirements really state the element: the component's role, the flow's endpoints and data, the target's number.
   - Nothing is invented: no region, account split, protocol, number or AWS service that the documents do not state. Unstated matters are UNDECIDED or open questions.
   - Boundaries and placements follow the documents. A component without a stated placement has no boundary.
   - Requirements are unchanged and none was dropped.
4. If anything is wrong, return findings to the parent: element ID, cited requirement IDs, what is wrong and why. Record `--decision rejected` only when the parent asks for a rejection record.
5. If everything holds, record it with `aws-design system review <overview> --decision accepted --actor <your actor> --reason "<what you compared>" --output <path>`. The CLI refuses the author's actor name and a draft with conflicts.

Your acceptance covers the draft's fidelity to its sources, not the system design. Afterwards the flow either records the agreement under an approved delegation policy (when the independent drafts agree and the findings are within the policy) or hands it to the person the user names; never record an agreement yourself.
