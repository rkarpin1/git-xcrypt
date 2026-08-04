# Synchronizacja `.gitattributes` z `.git-xcrypt` — krótki plan

> Pełny plan: `context/changes/gitignore-style-config/plan.md`

## Co i dlaczego

S-01 zostawia w `.gitattributes` jedną statyczną linię `* filter=git-xcrypt`, na
której wisi bezpieczeństwo. Ten element dokłada linie kosmetyczne (`-text`,
`diff=git-xcrypt`) i komendę `sync`, która je regeneruje po zmianie konfiguracji.

## Punkt wyjścia

Po S-01 istnieje parser `.git-xcrypt`, zapis sekcji zarządzanej między markerami
oraz CLI na `clap`. Sekcja zawiera wyłącznie linię catch-all.

## Pożądany stan końcowy

`git-xcrypt sync` regeneruje sekcję z `.git-xcrypt`, `sync --check` służy jako
bramka CI, a `init` od razu tworzy kompletną sekcję. Zapomnienie o `sync` nigdy nie
kosztuje sekretu — najwyżej gorszy `git diff`.

## Kluczowe podjęte decyzje

| Decyzja | Wybór | Dlaczego | Źródło |
| --- | --- | --- | --- |
| Zakres elementu | Tylko linie kosmetyczne | Rozjazd konfiguracji zniknął z konstrukcji w S-01 | Fundament |
| Negacje w `.gitattributes` | Pomijane | Brak sensownego odpowiednika; linie są kosmetyczne | Plan |
| `binary` | Linia bez `diff` | Odtwarza makro `binary` z gita | Fundament |
| Uszkodzone markery | Błąd `2` | Zgadywanie granic sekcji zniszczyłoby treść użytkownika | Plan |

## Zakres

**W zakresie:** tłumaczenie wzorców na składnię `.gitattributes`, renderowanie i
wstawianie sekcji, komenda `sync` wraz z `--check`, użycie tego samego kodu przez `init`.

**Poza zakresem:** linia catch-all (S-01), parser `.git-xcrypt` (S-01), wykrywanie
sekretów w historii (S-06).

## Architektura

`.git-xcrypt` → parser z S-01 → renderer sekcji → wstawienie między markery w
`.gitattributes`. Czysta funkcja konfiguracji; komenda tylko ją zapisuje.

## Fazy w skrócie

| Faza | Co dostarcza | Kluczowe ryzyko |
| --- | --- | --- |
| 1. Renderowanie | Sekcja jako funkcja konfiguracji | Zniszczenie treści użytkownika poza markerami |
| 2. `sync` | Komenda i bramka `--check` | Rozjazd z tym, co pisze `init` |

**Wymagania wstępne:** S-01.
**Szacowany nakład:** dwie krótkie fazy.

## Otwarte ryzyka i założenia

- Linie kosmetyczne mogą się zestarzeć; przyjęte świadomie, bo ich rozjazd nie
  kosztuje sekretu.
- Wzorce `.gitignore` i wzorce `.gitattributes` nie pokrywają się w stu procentach;
  tłumaczenie jest przybliżeniem, akceptowalnym w tej roli.

## Kryteria sukcesu

- `git check-attr` widzi `-text` i `diff` na ścieżkach objętych wzorcami.
- Dwa przebiegi `sync` dają identyczny plik.
- Treść `.gitattributes` poza markerami nigdy nie jest ruszana.
