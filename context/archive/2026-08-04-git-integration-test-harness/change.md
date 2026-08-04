---
change_id: git-integration-test-harness
title: "Git integration test harness"
roadmap_ref: F-01
status: archived
archived_at: 2026-08-04T09:02:05Z
created: 2026-08-04
updated: 2026-08-04
---

# Git integration test harness

Fundament testowy dla całego projektu: sposób automatycznego postawienia prawdziwego
repozytorium git w katalogu tymczasowym, zarejestrowania w nim filtra `clean`/`smudge`
i odczytania surowych bajtów tego, co faktycznie wylądowało w obiektach gita.

Element `F-01` z `context/foundation/roadmap.md`. Odblokowuje `S-01`, a przez zależność
również `S-03`, `S-04` i `S-06`.

## Artifacts

- `plan-brief.md` — dwustronicowy skrót
- `plan.md` — pełny plan implementacji
