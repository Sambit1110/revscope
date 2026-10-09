# ADR-0001: Evidence labels are derived from a closed set of result kinds

**Status:** accepted. Revised in Phase 3.6: the free-form labels on
capabilities were replaced by result kinds.

## Context

A requirements study of an existing tool found three problems:

- Evidence fell back to the strongest labels when a call site omitted them.
- The same decompiler output was labelled differently depending on which tool
  returned it.
- Mutation acknowledgements were labelled as facts about the original
  artifact.

The first Revscope design required labels but let each capability choose its
own confidence/authority pair. A review then showed that a capability named
`decompile` could declare `observed` / `analysis-state` and pass every rule.

## Decision

- **Kinds, not labels.** Every result has a `result_kind` from a closed list.
  One table maps each kind to its confidence, its authority, the subjects it
  may describe, whether reads or mutations produce it, and whether it must
  state a basis.
- **Producers choose a kind only.** Capabilities and evidence drafts carry a
  kind, never labels. `createEvidence` computes the labels.
- **Labels are checked against the table.** `parseEvidence` rejects records
  whose labels disagree with it.
- **Mutations acknowledge, reads observe.** Mutating capabilities must produce
  `mutation-acknowledgement`, and nothing else may.
- **Basis required for judgements.** Heuristic and assertion kinds must state
  their basis.
- **Identity covers everything semantic.** The identifier is an unkeyed digest
  of every semantic field. It establishes integrity consistency, not
  authenticity (see `docs/architecture.md`).

## Consequences

- A new provider cannot invent a label combination. It can still pick the
  wrong kind, for example `state-observation` for decompiler output, so
  provider reviews must check each declared kind against what the operation
  actually does.
- Adding a kind is a deliberate domain change, made in one table.
- The evidence schema changed to `revscope.evidence/2`.
