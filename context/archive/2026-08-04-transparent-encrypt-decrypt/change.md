---
id: transparent-encrypt-decrypt
title: Przezroczyste szyfrowanie w jednym repozytorium
roadmap_id: S-01
status: archived
created: 2026-08-04
archived_at: 2026-08-04T21:30:28Z
updated: 2026-08-04
---

# Przezroczyste szyfrowanie w jednym repozytorium

Gwiazda przewodnia roadmapy. Po tym elemencie wiadomo, czy reguła domenowa z PRD
działa: czy filtr gita potrafi szyfrować w locie, czy szyfrowanie jest powtarzalne
i czy `git status` po checkoucie zostaje czysty.

PRD: FR-001, FR-004, FR-005, §Business Logic
Roadmap: `context/foundation/roadmap.md` → S-01

## Przegląd implementacji

Dwa przebiegi `/10x-impl-review`, 2026-08-04 → `reviews/impl-review.md`. Pierwszy
przebieg zamknął cztery drogi, którymi wybrany plik trafiał jawny do bazy obiektów
z kodem wyjścia `0`, oraz rozjazd `text=auto` z gitem na samotnym `CR`, który psuł
determinizm. Format pliku i zamrożone wektory nie zmieniły się — poprawki dotyczyły
kodu, nie kontraktu na dysku.
