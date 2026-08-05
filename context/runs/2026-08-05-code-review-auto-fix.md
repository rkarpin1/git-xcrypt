# emi-code-review-auto-fix — 2026-08-05

Parametry: 1 runda × 3 etapy (domyślne). Gałąź `master`, SHA startowe `f9b5463`.
Baza przed przebiegiem: zielona (fmt OK, clippy 0 warnings, 439 testów, licenses ok).
Bramki: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`,
`cargo deny check licenses`.

## Runda 1

### Etap 1 — szeroki skan

**Zakres:** całość `src/` przeczytana w pełni (19 modułów + 9 komend), po wymiarach:
poprawność, bezpieczeństwo, współbieżność/TOCTOU, struktura wywołań
(`decide`↔filter/lock/diff/status, `gitindex`↔unlock/lock/status), otoczenie kodu, testy.

**Sprawdzone i czyste:** format i krypto (nagłówek AAD, fail-closed na
wersji/suite/flags, wektory RFC 5297); `keyfile` (Zeroizing kompletny, `holds_a_key`
współdzieli parser z `decode_portable`); `atomic` (O_EXCL, losowe nazwy, skracanie
≥ 224 B); `pktline`; `filter` (protokół, truncated-request); `gitconfig` (`key` vs
`key=`); `eol` (port `gather_stats` z korektą SUB); `repo` (worktree'y, commondir,
separate-git-dir); export/import/unlock/diff/init/sync; brak `println!` poza
dozwolonymi ścieżkami; jedyne dwa `expect` poza testami udokumentowane jako
nieosiągalne.

**Kandydaci: ~12 → ustalenia: 2.**

DO NAPRAWY (oba z testem czerwonym przed poprawką):

- `src/commands/lock.rs:496` — śledzony plik o kształcie residuum
  (`a.env.git-xcrypt-<hex>.tmp` przy deklaracji `*.env`) liczył się tylko po jednej
  stronie porównania „czy drzewo się ruszyło" → `lock` odmawiał **na zawsze**
  z komunikatem „run lock again". Poprawka: obie strony porównują pełny, posortowany,
  zdeduplikowany zbiór nazw; ochrona bez zmian (appear/vanish/typechange nadal
  odmawia, edycje łapie object-id). Commit `c113133`.
- `src/commands/status.rs:1234` — `--fix` czytał treść przez `fs::read` bez
  `symlink_metadata`: zadeklarowana ścieżka podmieniona na dowiązanie była czytana
  na wylot — plik spoza deklaracji szyfrowany do bazy obiektów, wpis indeksu
  przestawiony, ścieżka raportowana jako „fixed". Bliźniak zamkniętego wcześniej
  błędu w `Tracked::mode`; `lock`/`unlock`/`history` odmawiają symlinkom — to było
  jedyne czytanie drzewa bez pytania. Poprawka: `symlink_metadata` + `is_file`,
  ostrzeżenie, ścieżka zostaje w „in the clear" (kod 5). Commit `31ba43f`.

ODRZUCONE (najistotniejsze z ~10):

- `lock.rs:589` `core.bare == Some("true")` vs `is_true` — pisownia `bare=1` daje co
  najwyżej dodatkową odmowę, zgodną z zapisanym pochyleniem `lock`; git sam pisze
  wyłącznie `true` (kryteria 1/5).
- `filter.rs`: smudge bez `refresh_config_if_absent` — koszt to najwyżej brakujące
  ostrzeżenie i samonaprawialny EOL; decyzja „smudge z nagłówka" zapisana (kryterium 5).
- `status.rs`: `stale_section_note` milczy przy podwójnej sekcji — niebezpieczny
  skutek łapie `AttributeResolver` (kod 5), `sync` odmawia głośno (kryterium 4).
- `eol.rs`: brak round-tripu `\r\r\n` przy jawnym `text` — otwarta decyzja 8
  w `zalozenia.md` (kryterium 5).
- `init.rs` `create_config_file` przez `fs::write` — urwany zapis szablonu z samych
  komentarzy nie ma obserwowalnego skutku (kryterium 2).

### Etap 2 — adwersarz

**Zakres:** obie naprawy etapu 1 (osiągalność regresji, utracona ochrona, testy
przechodzące z niewłaściwego powodu), wszystkie odrzucenia etapu 1, plus obszary
nietknięte: harness w całości, `acceptance.rs`, `filter_edge_cases.rs`,
`decrypted_diff.rs`, `format_vectors.rs`, `ci.yml`.

**Wynik:** obie naprawy się bronią (porównanie pełnozbiorowe nie przepuszcza żadnej
realnej zmiany; blokada symlinka nie zatrzymuje żadnego legalnego przepływu); żadnego
odrzucenia nie cofnięto; `break_filter` w harnessie celowo nie ustawia `required` —
strażnik z `AGENTS.md` żywy. **Kandydaci nowi: 0. Cofnięte: 0.**

### Etap 3 — kompletność

**Zakres:** domknięcie nieprzeczytanych obszarów: `gitattributes.rs` 1100–1551,
`gitindex.rs` 998–1532, `history.rs` 818–1076, pełna lista 57 testów
`status_command.rs`, `deny.toml`, `release.yml`, `Cargo.toml`.

**Kandydaci: 1 → ustalenia: 1.**

- `tests/status_command.rs:724` — test **niestabilny**: fixtura polegała na tym, że
  gołe `git add -A` ponownie przefiltruje niezmieniony plik po dopisaniu wzorca, co
  dzieje się wyłącznie w oknie racy-clean (zmierzone: 2 porażki na ~15 przebiegów).
  Poza oknem git ufa cache'owi stat — dokładnie ta luka, dla której istnieje `--fix` —
  i status uczciwie odpowiada `5` tam, gdzie test asertuje `6`. Naprawiona fixtura
  (nie asercja): `git add --renormalize .` wymusza filtr niezależnie od stat;
  5× pełny przebieg zielony. Commit `778d499`.

## Podsumowanie

| | |
|---|---|
| Commity przebiegu | `c113133`, `31ba43f`, `778d499` |
| Ustalenia / kandydaci | 3 / ~13 (stosunek odrzuconych ~10:3) |
| Nierozstrzygnięte | 0 |
| Cofnięte | 0 |
| Bramki po przebiegu | fmt OK · clippy 0 warnings · **441 passed, 0 failed** · licenses ok |
| Zamrożone kontrakty | nietknięte (format, klucz, kody wyjścia, wektory) |

Kontrola jakości raportu: każde `DO NAPRAWY` ma nazwaną ścieżkę osiągalności i test
czerwony przed poprawką; stosunek odrzuconych do naprawionych zdrowy (~10:3); żadna
naprawa nie jest przepisaniem działającego kodu w równoważny kształt.

Dla człowieka: nic nie czeka — przebieg nie zostawił pozycji nierozstrzygniętych.
