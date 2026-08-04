---
id: gitignore-style-config
title: Synchronizacja .gitattributes z .git-xcrypt
roadmap_id: S-02
status: impl_reviewed
created: 2026-08-04
updated: 2026-08-04
---

# Synchronizacja `.gitattributes` z `.git-xcrypt`

Po decyzji o konstrukcji catch-all i po przeniesieniu obsługi końców linii do
S-01, ten element odpowiada za drugą połowę pary: generowanie **kosmetycznych**
linii w `.gitattributes` i komendę `sync`.

PRD: FR-003 (FR-002 realizuje parser z S-01)
Roadmap: `context/foundation/roadmap.md` → S-02
