<!-- IMPL-REVIEW-REPORT -->
# Przegląd implementacji: Read `.gitattributes` from the path's ancestors

- **Plan**: context/changes/attribute-stack-walks-ancestors/plan.md
- **Zakres**: Fazy 1–2 z 2 (pełny przegląd planu)
- **Data**: 2026-08-07
- **Werdykt**: ZAAKCEPTOWANY
- **Ustalenia**: 0 krytycznych, 1 ostrzeżenie, 4 obserwacje
- **Metoda**: dwóch równoległych agentów (odchylenia od planu; bezpieczeństwo/jakość/wzorce) + niezależny przebieg kryteriów automatycznych w sesji głównej (130 testów / 0 porażek, fmt, clippy, cztery budżety `--release`).

## Werdykty

| Wymiar | Werdykt |
|-----------|---------|
| Zgodność z planem | WARNING (F1, F2) |
| Dyscyplina zakresu | PASS — żadna bariera „What We Are NOT Doing" nieprzekroczona; `Cargo.toml`, format i bajty na dysku nietknięte |
| Bezpieczeństwo i jakość | PASS (obserwacje F3, F4) |
| Architektura | PASS — precedencja w jednym miejscu (`assemble`), kierunek fail-open/fail-closed niezmieniony, nic na stdout |
| Spójność wzorców | PASS (obserwacja F5) |
| Kryteria sukcesu | PASS — zweryfikowane niezależnie |

Odnotowane bez ustalenia: zapas 500× czwartego budżetu zamiast planowych 2–4× — świadome odstępstwo, udokumentowane w samym teście i w `prd.md` (I/O vs scheduler; mutacja jednoznaczna: 43,6 ms wobec budżetu 10 ms).

## Ustalenia

### F1 — Strażnik permutacji nie asertował osi `eol`

- **Ważność**: ⚠️ OSTRZEŻENIE
- **Wpływ**: 🏃 NISKI — szybka decyzja; poprawka oczywista i wąska
- **Wymiar**: Zgodność z planem
- **Lokalizacja**: src/git/attributes.rs (test `the_order_paths_are_resolved_in_never_changes_an_answer`)
- **Szczegóły**: Plan kazał porównywać osie `filter`, `text` i `eol`; test porównywał dwie pierwsze.
- **Poprawka**: asercja `ours.eol` wobec `git check-attr eol`, plus pełna rekonstrukcja werdyktu konwersji (ta sama co w `agrees_with_git`: `text` → legacy `crlf` → goły `eol=`), bo uproszczona wersja fałszywie oblewała ścieżkę z gołym `eol=crlf`.
- **Decyzja**: NAPRAWIONE (razem z F6, jeden commit)

### F2 — Kryterium 2.5 odhaczone przy 24 ms vs „rzędu 10 ms"

- **Ważność**: 📝 OBSERWACJA
- **Wpływ**: 🏃 NISKI
- **Wymiar**: Zgodność z planem
- **Lokalizacja**: plan.md, wiersz Progress 2.5
- **Szczegóły**: Zmierzone 24 ms na mniejszym drzewie niż przeglądowe (sam stos 0,02 ms; reszta to git + start filtra). Rozbieżność nazwana wprost przy bramce ręcznej i potwierdzona przez właściciela przed odhaczeniem.
- **Decyzja**: ZAAKCEPTOWANE (decyzja właściciela przy bramce ręcznej)

### F3 — Ścieżka z wiodącym `/` sondowała poza drzewem roboczym

- **Ważność**: 📝 OBSERWACJA
- **Wpływ**: 🏃 NISKI
- **Wymiar**: Bezpieczeństwo i jakość
- **Lokalizacja**: src/git/attributes.rs, `probe_ancestors`
- **Szczegóły**: `Path::join` z argumentem absolutnym zastępuje bazę, więc `probe_ancestors(b"/x/…")` sondowałoby `/x/.gitattributes`. Nieosiągalne przy prawdziwym gicie (pathname= i indeks znormalizowane — zapisane założenie), ale to jedyne miejsce, gdzie bajty ścieżki stają się ścieżką systemu plików.
- **Poprawka**: wczesny `return` przy wiodącym `/`, z komentarzem nazywającym dziedziczone założenie normalizacji.
- **Decyzja**: NAPRAWIONE

### F4 — Docstring sondy pomijał trzecią różnicę wobec spaceru

- **Ważność**: 📝 OBSERWACJA
- **Wpływ**: 🏃 NISKI
- **Wymiar**: Bezpieczeństwo i jakość (dokumentacja)
- **Lokalizacja**: src/git/attributes.rs, `probe_ancestors`
- **Szczegóły**: Na ext4 z `core.ignorecase=true` spacer znajdował plik atrybutów z listingu i foldował go do innej pisowni katalogu; sonda pyta o pisownię pytanej ścieżki — dokładnie jak git. Zmiana w kierunku gita, ale niezapisana — ktoś mógł ją „naprawić" z powrotem.
- **Poprawka**: docstring wymienia obie różnice wprost, z zakazem „do not fix this back toward the walk".
- **Decyzja**: NAPRAWIONE

### F5 — `sources()` zostało publicznym API bez odbiorcy

- **Ważność**: 📝 OBSERWACJA
- **Wpływ**: 🔎 ŚREDNI — prawdziwy kompromis
- **Wymiar**: Spójność wzorców
- **Lokalizacja**: src/git/attributes.rs
- **Szczegóły**: Jedyny konsument (nota `status`) przeszedł na `attribute_files_under`; `sources()` nie miało ani jednego wywołania. Projekt usuwa kod bez właściciela (precedens: `import-key`).
- **Poprawka A ⭐ (wybrana)**: usunięcie akcesora i pola `sources` wraz z całym doprowadzeniem w `assemble`; komentarz w miejscu usunięcia mówi, czemu akcesora nie ma i czemu nota nie może z niego czytać.
- **Poprawka B (odrzucona)**: zostawić z dopiskiem „bez odbiorcy".
- **Decyzja**: NAPRAWIONE (wariant A)

### F6 — Strażnik permutacji sam nie łapał zgubienia globala przy przebudowie

- **Ważność**: 📝 OBSERWACJA
- **Wpływ**: 🏃 NISKI
- **Wymiar**: Kryteria sukcesu (pokrycie)
- **Lokalizacja**: src/git/attributes.rs (test permutacji)
- **Szczegóły**: Globalne `*.env -filter` było w teście wszędzie przesłonięte przez catch-all z korzenia; regułę trzymał inny scenariusz, nie z tej intencji.
- **Poprawka**: piąta ścieżka `notes.txt`, której `eol` odpowiada wyłącznie plik globalny (`*.txt eol=crlf`); mutacja `self.global → None` przy przebudowie zweryfikowana na czerwono i wycofana.
- **Decyzja**: NAPRAWIONE (razem z F1, jeden commit)

## Sortowanie — podsumowanie

- Naprawione: F1, F3, F4, F5 (wariant A), F6 — jeden commit napraw przeglądowych
- Zaakceptowane: F2 (decyzja właściciela przy bramce ręcznej)
- Pominięte: —
