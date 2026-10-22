# Design Documentation

This directory contains maintained design notes for the SDK. READMEs cover
setup and usage; these pages describe interfaces, invariants, trust boundaries,
compatibility decisions, and verification strategy.

## Index

| Topic | Document |
|---|---|
| Workspace layers, modules, and attestation flows | [Architecture overview](../ARCHITECTURE.md) |
| Offline SNP report verification and VCEK binding | [SNP verification](snp-verification.md) |

## Maintaining These Pages

- Keep one page per coherent design topic and link related topics rather than
  duplicating their explanations.
- Update the relevant page in the same change that alters its public contract,
  trust boundary, or compatibility rules.
- Describe implemented behavior separately from limitations or future work.
- Link to owning source and tests; keep transient investigation notes, sample
  acquisition history, and execution logs out of these pages.
- Add new topics to this index so the documentation remains navigable.

[Repository overview](../README.md)