# Read `.gitattributes` from the path's ancestors — Plan Brief

> Pełny plan: `context/changes/attribute-stack-walks-ancestors/plan.md`

## What and why

Stos atrybutów gita (`AttributeResolver`) przechodzi dziś **całe drzewo
robocze** w poszukiwaniu `.gitattributes`, choć git czyta te pliki wyłącznie
z katalogów na ścieżce pytanego pliku. Zmierzone: `git add` jednego
zadeklarowanego pliku w repozytorium z dużym katalogiem budowania kosztuje
**220 ms zamiast 10 ms** — jedyna pozycja w produkcie skalująca się z liczbą
plików nieśledzonych. Zmieniamy odkrywanie źródeł na leniwe sondowanie
przodków; składanie precedencji zostaje dosłownie dzisiejsze.

## Starting point

`collect_attribute_files` (`attributes.rs:942`) spaceruje po całym drzewie
przy pierwszym użyciu resolvera. Na resolverze stoi odmowa ścieżki `clean`
przy `required = true` — błąd w precedencji kosztuje albo zablokowane
repozytorium, albo plik nie do odzyskania. Przegląd 2026-08-06 zmierzył
problem, odrzucił trzy warianty przycięcia (po `.gitignore`, po indeksie, po
zagnieżdżonym `.git`) i świadomie nie naprawiał sam — zmiana wymaga planu.

## Desired end state

`git add` zadeklarowanego pliku wraca do rzędu 10 ms niezależnie od rozmiaru
katalogów ignorowanych. Odpowiedzi resolvera bajt w bajt identyczne
(parytet z żywym `git check-attr`), nota `status` o obcych liniach `filter`
niezmieniona co do treści i pokrycia, a czwarty budżet w `performance.rs`
czerwieni powrót pełnego spaceru.

## Key decisions

| Decyzja | Wybór | Dlaczego | Źródło |
| --- | --- | --- | --- |
| Mechanizm leniwości | Sonda przodków + **pełna przebudowa `Search` przy odkryciu**, dzisiejszym kodem konstrukcji | Zero nowej logiki precedencji — każda przebudowa to ten sam, przetestowany tor; przebudów tyle, ile plików atrybutów na łańcuchach (0–2) | Plan |
| Przyrostowe dokładanie do `Search` | Odrzucone | Poprawność wisiałaby na nieudokumentowanej semantyce kolejności list gix — klasa błędu, przed którą ostrzegał przegląd | Plan |
| `gix-worktree::Stack` | Odrzucone | Nowa zależność i przepisanie wnętrza resolvera — największy promień zmiany na najgorętszej regule | Plan |
| Nota `status` (`sources()`) | **Status dalej chodzi po całym drzewie**, osobną enumeracją tylko dla noty | Nota istnieje po to, żeby nazwać plik sięgający ścieżek jeszcze nieśledzonych — leniwe źródła by go zgubiły; `status` to komenda diagnostyczna, ~210 ms akceptowalne | Plan |
| Warianty przycięcia | Nie wracamy do żadnego | Odrzucone z powodami: każde przycięcie ma kierunek kosztujący plik | Badania (przegląd 2026-08-06) |
| Dowód wydajnościowy | **Nowy przypadek `#[ignore]` w `performance.rs`** + pomiar ręczny przed/po jako liczby źródłowe | Regresja łapalna komendą; wymaga dopisania czwartego budżetu do PRD §NFR | Plan (decyzja właściciela) |
| Kryterium akceptacji | Parytet z gitem + strażnik kolejności odkrywania, zmutowany w obie strony | Jedyny wymiar, który tylko leniwość może zepsuć, dostaje własnego strażnika | Plan |

## Scope

**W zakresie:** leniwe odkrywanie w `AttributeResolver`; osobna enumeracja
pełnego drzewa dla noty `status`; strażnik kolejności odkrywania; czwarty
budżet `performance.rs`; zapis w `prd.md`, `zalozenia.md`, `AGENTS.md`.

**Poza zakresem:** przycinanie po `.gitignore`/indeksie/`.git`;
`gix-worktree`; zmiany w `smudge`/`sync`/`lock`/`unlock`; cokolwiek
dotykającego bajtów na dysku; `F_FULLFSYNC` w `lock`/`unlock`.

## Architecture / Approach

`resolve(path)` domyka sondowanie łańcucha przodków (`symlink_metadata` na
`<dir>/.gitattributes`, każdy katalog raz na proces); nowy plik → przebudowa
`Search` funkcją wyjętą z dzisiejszego `::new` (globals → posortowane źródła
drzewa + kopie indeksowe → `info` na końcu). Kolejność między rozłącznymi
gałęziami nie wpływa na wynik (wzorce ograniczone do poddrzewa źródła), więc
jedyny porządek, który się liczy, składa ta sama funkcja co dziś.

## Phases at a glance

| Faza | Co dostarcza | Kluczowe ryzyko |
| --- | --- | --- |
| 1. Lazy resolver | Mechanizm + parytet z gitem + strażnik kolejności + nota `status` bez zmian | Precedencja pod odmową `clean` — mitygowane przebudową istniejącym kodem i mutacjami w obie strony |
| 2. Budget + record | Czwarty przypadek `performance.rs`, pomiar przed/po, zapis w PRD/zalozenia/AGENTS | Próg zależny od I/O — mitygowane zapasem 2–4× i pomiarem minimum z 5 przebiegów |

**Wymagania wstępne:** czyste drzewo na `master`; zielona baza (127 testów po przeglądzie 2026-08-07).
**Szacowany nakład:** ~1–2 sesje, 2 fazy.

## Open risks and assumptions

- Zbiór wysondowanych katalogów kluczowany bajtami ścieżki — przy
  `core.ignorecase` druga pisownia katalogu kosztuje drugą sondę (nie błąd,
  koszt); zapisane w komentarzu.
- Znika wykluczenie katalogów-dowiązań (spacer nie wchodził, sonda stat-uje
  przez ścieżkę) — kierunek zgodny z gitem, przypadek teoretyczny dla ścieżek,
  o które git pyta; udokumentowane w planie.
- Budżet fazy 2 dobierany po pomiarze (zapas 2–4×), nie zgadywany z góry.

## Success criteria (summary)

- `git add` zadeklarowanego pliku w drzewie z katalogiem budowania: rząd 10 ms
  (z ~220 ms), potwierdzone pomiarem przed/po.
- Odpowiedzi resolvera identyczne z `git check-attr` we wszystkich istniejących
  i nowych scenariuszach; strażnik kolejności zmutowany w obie strony.
- Powrót pełnego spaceru czerwieni czwarty przypadek `performance.rs`.
