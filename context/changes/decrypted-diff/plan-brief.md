# Różnice na treści odszyfrowanej — krótki plan

> Pełny plan: `context/changes/decrypted-diff/plan.md`

## Co i dlaczego

`git diff` na pliku szyfrowanym pokazuje dziś szum albo `Binary files differ`. Ten
element podpina sterownik `textconv`, więc git porównuje treść jawną.

## Punkt wyjścia

Po S-01 istnieje `crypto::decrypt` i wykrywanie magic; po S-02 sekcja zarządzana w
`.gitattributes` zawiera już `diff=git-xcrypt` na wzorcach. Brakuje wyłącznie
sterownika po stronie `.git/config`.

## Pożądany stan końcowy

`git diff`, `git log -p` i `git show` pokazują treść jawną dla plików objętych
wzorcami. Bez klucza komenda kończy się czytelnym błędem zamiast wypisywać szum.

## Kluczowe podjęte decyzje

| Decyzja | Wybór | Dlaczego | Źródło |
| --- | --- | --- | --- |
| Mechanizm | `textconv` | Standardowy sposób pokazywania różnic na przekształconej treści | Fundament |
| `cachetextconv` | Nie ustawiamy | Bufor trzymałby treść jawną w `.git/` | Plan |
| Treść bez magic | Przepuszczana | Inaczej `git log -p` przestaje działać na starej historii | Plan |
| Wspólny kod | `crypto::decrypt` z S-01 | Trzecia ścieżka deszyfrowania nie może się rozjechać z formatem | Fundament |

## Zakres

**W zakresie:** komenda `diff` jako sterownik `textconv`, rejestracja w `init`.

**Poza zakresem:** zmiany formatu, `cachetextconv`, osobna obsługa `difftool`.

## Architektura

```
git diff ──► diff.git-xcrypt.textconv ──► git-xcrypt diff <plik tymczasowy>
                                              └─► crypto::decrypt ──► stdout
```

Uwaga: `textconv` dostaje ścieżkę pliku, nie treść na `stdin` — inaczej niż filtr.

## Fazy w skrócie

| Faza | Co dostarcza | Kluczowe ryzyko |
| --- | --- | --- |
| 1. Sterownik `textconv` | Różnice na treści jawnej | Wywalenie się na treści niezaszyfrowanej psuje `git log -p` |

**Wymagania wstępne:** S-01 (i S-02 dla linii `diff` w sekcji).
**Szacowany nakład:** jedna krótka faza.

## Otwarte ryzyka i założenia

- Treść jawna przechodzi przez `stdout` procesu potomnego; to jest cel komendy, ale
  oznacza, że wynik trafia tam, gdzie git go skieruje.
- Bez `cachetextconv` każdy `git log -p` deszyfruje od nowa; przy plikach
  konfiguracyjnych koszt jest pomijalny.

## Kryteria sukcesu

- `git diff` pokazuje linie plaintextu i żadnych bajtów magic.
- `git log -p` działa na historii sprzed konfiguracji.
- Bez klucza komenda kończy się kodem `3`, a nie szumem na ekranie.
