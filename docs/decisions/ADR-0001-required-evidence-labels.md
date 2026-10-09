# ADR-0001: Evidence labels are derived from a closed set of result kinds

**Status:** accepted. Revised in Phase 3.6: the free-form labels on
capabilities were replaced by result kinds. Revised again in the Phase 3.6
hardening pass: acknowledgements became `reported`, and provider declarations
are checked against the subject they describe.

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
  `mutation-acknowledgement`, and nothing else may. An acknowledgement's
  confidence is `reported`, a level used for nothing else: it records what the
  provider says it did, not an observation of the resulting state.
- **Declarations are checked in context.** A session checks each provider
  capability against the analysis-state subject its results will describe, so
  a provider cannot declare kinds that speak for the original artifact. The
  session's `observe_state` operation is reserved, and operation names,
  effects and limitations are validated at runtime.
- **Basis required for judgements.** Heuristic and assertion kinds must state
  their basis.
- **Identity covers everything semantic.** The identifier is an unkeyed digest
  of every semantic field. It is a consistency check that catches accidental
  changes. Because anyone can recompute it, it establishes neither integrity
  against deliberate edits nor authenticity (see `docs/architecture.md`).

## Consequences

- A new provider cannot invent a label combination. It can still pick the
  wrong kind, for example `state-observation` for decompiler output, so
  provider reviews must check each declared kind against what the operation
  actually does.
- Adding a kind is a deliberate domain change, made in one table.
- The evidence schema changed to `revscope.evidence/2`, then to
  `revscope.evidence/3` when the `reported` confidence level was added and
  acknowledgements moved to it. Records of earlier schemas are rejected
  rather than reinterpreted.
