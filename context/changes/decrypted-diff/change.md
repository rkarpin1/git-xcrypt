---
id: decrypted-diff
title: Różnice na treści odszyfrowanej
roadmap_id: S-05
status: impl_reviewed
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
- **`cachetextconv` jest zapisywane jawnie jako `false`, nie „nieustawiane".** Plan
  mówił „nie ustawiamy"; zmierzone: to za mało. `[diff "git-xcrypt"] cachetextconv
  = true` w `~/.gitconfig` jest dziedziczone, a brak wpisu lokalnego niczego nie
  przebija — po `git log -p` odszyfrowane pliki lądowały w
  `refs/notes/textconv/git-xcrypt` i przeżywały `lock` z usuniętym kluczem.
  Dopiero lokalne `false` wygrywa. Cache, który już istnieje, jest **raportowany,
  nie kasowany**: usunięcie refa zostawiłoby obiekty w bazie, więc komunikat
  „posprzątane" byłby nieprawdą — ta sama postawa, którą produkt ma wobec jawnej
  treści w historii.
- **Gałąź deszyfrująca wypisuje postać gitową (LF), nie roboczą.** Plan nie
  rozstrzygał końców linii. Ta gałąź jest osiągalna tylko wtedy, gdy smudge nie
  zadziałał przed sterownikiem — a wtedy obie strony różnicy są ciphertextem i obie
  przechodzą tą samą drogą, więc wyjście zależy wyłącznie od bloba, nie od
  `core.autocrlf` maszyny.
- **Podkomenda `diff` nie ma własnego `--help` i przyjmuje ścieżki zaczynające się
  od myślnika.** Git podaje ścieżkę względną repozytorium bez `./` z przodu, więc
  plik o nazwie `--help` w korzeniu wypisywał tekst pomocy na `stdout` z kodem `0`,
  a git pokazywał go jako treść pliku; plik o nazwie `-w.env` przerywał `git diff`.
- **`diff` odmawia dla pliku klucza — po treści, nie po położeniu.** Plik klucza ma
  własne magic, więc szedł gałęzią przepuszczającą i
  `git-xcrypt diff .git/git-xcrypt/keys/default` wypisywał klucz główny na `stdout`.
  Pierwsza wersja zabezpieczenia sprawdzała ścieżkę względem katalogu gita i była
  omijalna przez katalog bieżący (uruchomienie spoza repozytorium przepuszczało
  klucz), przez twarde dowiązanie i przez kopię z `export-key` leżącą w drzewie
  roboczym. Rozstrzyga więc `keyfile::holds_a_key` na treści; kontrola ścieżki
  została jako druga warstwa. Reguła „klucz nigdy na `stdout` poza `export-key`"
  nie ma wyjątków.
