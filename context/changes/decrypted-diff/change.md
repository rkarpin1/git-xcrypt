---
id: decrypted-diff
title: Różnice na treści odszyfrowanej
roadmap_id: S-05
status: implemented
created: 2026-08-04
updated: 2026-08-04
---

# Różnice na treści odszyfrowanej

Trzecia ścieżka deszyfrowania obok clean i smudge. Musi dzielić kod z pozostałymi,
inaczej rozjedzie się z formatem przy pierwszej jego zmianie.

PRD: FR-006
Roadmap: `context/foundation/roadmap.md` → S-05

## Rozbieżności planu wobec zmierzonego zachowania gita

Zmierzone na git 2.55 przy implementacji, 2026-08-04:

- **Plan zakładał, że `textconv` dostaje ciphertext. Nie dostaje.** Git materializuje
  każdą stronę różnicy przez `convert_to_working_tree` (czyli smudge) *zanim* poda
  ją sterownikowi, a stronę z katalogu roboczego pożycza wprost. Sterownik dostaje
  więc plaintext w obu przypadkach, a gałąź deszyfrująca jest zabezpieczeniem, nie
  ścieżką główną. To, co daje sama rejestracja sterownika, to porównanie treści jako
  tekstu zamiast `Binary files differ` na surowym ciphertexcie — i to wystarcza, żeby
  FR-006 był spełniony.
- **Konsekwencja: `lock` musi wyrejestrować `diff.git-xcrypt.textconv`.** Skoro
  textconv wciąga smudge, w repozytorium bez klucza filtr odmawia, `required = true`
  zamienia to w `fatal: smudge filter git-xcrypt failed`, i `git log -p` przestaje
  działać dla każdej zadeklarowanej ścieżki. Bez sterownika git wypisuje
  `Binary files differ`, co jest uczciwą odpowiedzią dla repozytorium, którego nikt
  nie może odczytać. `unlock` i `import-key` rejestrują go z powrotem.
- **`cachetextconv` jest aktywnie usuwane, nie tylko nieustawiane** — trzymałoby
  odszyfrowaną treść w refie notatek wewnątrz `.git/`, gdzie przeżyłaby `lock`.
