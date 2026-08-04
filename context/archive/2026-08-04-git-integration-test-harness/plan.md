# Git integration test harness — Implementation Plan

## Overview

Budujemy fundament testowy `F-01`: moduł pomocniczy, który stawia prawdziwe repozytorium git
w katalogu tymczasowym, rejestruje w nim naszą binarkę jako filtr `clean`/`smudge`, wykonuje
commit i pozwala odczytać **surowe bajty** bloba zapisanego w obiektach gita.

Powód, dla którego to jest osobny element roadmapy: determinizm szyfrowania i brak uszkodzeń
treści są obserwowalne **wyłącznie** przez to, co git faktycznie zapisał. Ręczne sprawdzenie
tych własności ich nie wychwyci, a każdy kolejny element (`S-01`, `S-03`, `S-04`, `S-06`)
opiera swój dowód na tym samym mechanizmie.

Ponieważ prawdziwy filtr jeszcze nie istnieje, harness napędza **ukrytą komendę `__test-filter`**
w naszej binarce — odwracającą bajty, a więc odwracalną i deterministyczną. `S-01` podmienia
wnętrze transformacji na AES-256-SIV, nie ruszając harnessu.

## Current State Analysis

- `src/main.rs:1-3` to hello world. Brak podziału `lib` + `bin`, którego wymaga
  `context/foundation/zalozenia.md` §Założenia techniczne.
- `Cargo.toml:7` deklaruje pustą sekcję `[dependencies]`. Brak `tests/`.
- Historia repozytorium: jeden commit (`95bc76d`), stan czysty.
- Środowisko zweryfikowane sondą: rustc 1.97.1, cargo 1.97.1, git 2.55.0, macOS.
- `cargo audit` przechodzi, ale bez wartości informacyjnej — projekt nie ma zależności
  (`context/changes/bootstrap-verification/verification.md:90-106`).

## Desired End State

Po zakończeniu planu `cargo test` uruchamia zestaw testów integracyjnych, które na prawdziwym
repozytorium git dowodzą, że:

1. treść zapisana w obiekcie gita **różni się** od treści w katalogu roboczym,
2. checkout odtwarza treść **bajt w bajt**, a `git status` po nim jest **czysty**,
3. klon bez skonfigurowanego filtra pokazuje w katalogu roboczym treść bloba,
4. pliki puste i binarne przechodzą przez ten cykl bez zniekształcenia,
5. **awaria filtra przerywa operację gita** zamiast wpuścić plaintext do indeksu.

Weryfikacja: `cargo test` zielone, `cargo clippy --all-targets -- -D warnings` bez uwag,
`cargo fmt --check` czyste.

### Key Discoveries

- **`filter.<nazwa>.required = true` jest warunkiem koniecznym gwarantki bezpieczeństwa.**
  Sonda na git 2.55.0: bez tej flagi filtr `clean` kończący się kodem `3` daje `git add`
  **kod wyjścia 0**, a do commita trafia **plaintext**. Git traktuje awarię filtra jako
  nieszkodliwą i przepuszcza treść bez zmian. Z flagą: `fatal: <plik>: clean filter '<nazwa>' failed`,
  plik **nie wchodzi do indeksu**, operacja przerwana.
  To **koryguje** `context/foundation/zalozenia.md` §Integracja z git, które twierdzi, że git
  przerywa operację przy niezerowym kodzie filtra bez żadnego warunku.
- **Klon bez skonfigurowanego filtra kończy się kodem 0 i pokazuje treść bloba w katalogu roboczym.**
  Potwierdzone sondą. To czyni kryterium 5 z `prd.md` §Success Criteria sprawdzalnym wprost.
- **Git uruchamia polecenie filtra przez powłokę**, więc ścieżka do binarki wymaga cytowania —
  ścieżki `target/` z odstępami w nazwie inaczej rozpadną się na argumenty.
- **`env!("CARGO_BIN_EXE_git-crypt")`** daje testowi integracyjnemu ścieżkę do zbudowanej
  binarki bez zgadywania układu `target/`. Nazwa celu binarnego jest równa nazwie pakietu.
- **Odwrócenie bajtów jest inwolucją** (`rev(rev(x)) == x`), więc jedna komenda pełni rolę
  zarówno `clean`, jak i `smudge`. Wymaga zbuforowania całego wejścia — tak samo jak AES-SIV,
  który potrzebuje dwóch przebiegów po danych, więc harness od razu ćwiczy właściwy kształt.

## What We Are NOT Doing

- **Żadnej kryptografii** — brak AES-SIV, brak wyboru szyfru, brak zależności kryptograficznych.
- **Żadnego formatu pliku** — brak magic, wersji formatu, identyfikatora klucza. To zapada w `S-01`.
- **Żadnych prawdziwych komend CLI** — `init`, `status`, `lock`, `unlock`, `export-key` nie powstają.
  Nie wprowadzamy też biblioteki do parsowania argumentów; wybór `clap` vs alternatywa należy do `S-01`.
- **Żadnego zarządzania kluczem** — katalog `.git/git-crypt/keys/` nie powstaje.
- **Żadnego pliku `.git-crypt`** ani generowania `.gitattributes` — to `S-02`.
- **Żadnego CI** — workflow GitHub Actions należy do `S-07`. Kod ma być przenośny, ale
  przenośność nie jest w tym elemencie dowodzona empirycznie na trzech platformach.
- **Żadnej poprawki `zalozenia.md`** — błąd opisany w Key Discoveries jest odnotowany,
  ale edycja dokumentu fundamentowego jest osobną pracą.

## Implementation Approach

Trzy fazy, każda kończąca się stanem weryfikowalnym samodzielnie:

1. **Obiekt do napędzania** — crate dzieli się na `lib` + cienki `bin`, powstaje `__test-filter`.
   Weryfikowalne bez gita, samym potokiem `stdin`/`stdout`.
2. **Pionowy przekrój harnessu** — repozytorium, rejestracja filtra, commit, odczyt bloba.
   Weryfikowalne jednym testem: blob różni się od pliku roboczego.
3. **Klon, asercje i przypadki brzegowe** — drugie repozytorium, cienka warstwa asercji,
   testy pliku pustego, binarnego, czystego `status` i awarii filtra.

Warstwa asercji jest cienka **z wyboru**: podstawą API są surowe `Vec<u8>`, a asercje to
wygoda nad nimi. W `F-01` nie istnieje jeszcze pojęcie „zaszyfrowany", więc asercja
`assert_blob_encrypted` musiałaby zgadywać format, który zapada dopiero w `S-01`.

## Critical Implementation Details

- **`required = true` ustawiane przy rejestracji filtra, nie opcjonalnie.** Harness, który
  rejestruje filtr bez tej flagi, cicho dopuszcza plaintext do indeksu przy każdej awarii —
  czyli produkuje testy przechodzące w sytuacji, którą projekt uznaje za katastrofę.
- **Cała ścieżka odczytu operuje na `Vec<u8>`, nigdy na `String`.** Ciphertext (a w `F-01`
  odwrócone bajty pliku binarnego) nie jest poprawnym UTF-8. `String::from_utf8` na tej
  ścieżce zamieni realny test w test, który nigdy się nie uruchomi.
- **`stdout` binarki na ścieżce filtra: wyłącznie `io::stdout().lock().write_all(...)` + `flush()`.**
  Żadnego `println!`, żadnego `dbg!`. Reguła obowiązuje już dla `__test-filter`, mimo że
  przenosi tylko dane testowe — nawyk zapada tutaj i przechodzi do `S-01`.
- **Kolejność w fazie 2 ma znaczenie:** `git init` → konfiguracja tożsamości → rejestracja
  filtra → zapis `.gitattributes` → zapis pliku → `git add`. Zapis pliku przed rejestracją
  filtra nie zaszkodzi, ale `git add` przed zapisem `.gitattributes` przepuści treść bez filtra
  i test cicho straci sens.

## Phase 1: Crate split and the `__test-filter` command

### Overview

Crate zyskuje strukturę `lib` + cienki `bin` i pierwszy obiekt, który git może uruchomić jako filtr.

### Changes Required:

#### 1. Struktura crate'a

**Plik**: `Cargo.toml`

**Cel**: dodać `thiserror` jako zależność biblioteki (wymóg `AGENTS.md` §Conventions) oraz
`tempfile` w `dev-dependencies` na potrzeby faz 2-3. Cele `lib` i `bin` cargo wykrywa
automatycznie z obecności `src/lib.rs` i `src/main.rs` — nie deklarujemy ich jawnie.

**Kontrakt**: sekcja `[dependencies]` zawiera `thiserror`; nowa sekcja `[dev-dependencies]`
zawiera `tempfile`. Nazwa pakietu pozostaje `git-crypt`, bo od niej zależy
`CARGO_BIN_EXE_git-crypt` używane w fazie 2.

#### 2. Biblioteka

**Plik**: `src/lib.rs`

**Cel**: przenieść logikę poza binarkę, żeby była testowalna bezpośrednio, i wystawić
transformację napędzaną przez filtr. Transformacja odwraca kolejność bajtów — jest
odwracalna, deterministyczna i sama sobie odwrotna, więc jedna funkcja obsługuje
`clean` i `smudge`.

**Kontrakt**: publiczny typ błędu oparty na `thiserror` oraz publiczna funkcja przenosząca
dane z czytnika do pisarza z zastosowaną transformacją, o sygnaturze przyjmującej
`&mut impl Read` i `&mut impl Write` i zwracającej `Result<(), Error>`. Brak `unwrap()`
na tej ścieżce. Funkcja buforuje całe wejście przed zapisem — to świadome, wymuszone
przez odwracanie i zgodne z dwuprzebiegową naturą SIV.

#### 3. Binarka

**Plik**: `src/main.rs`

**Cel**: sprowadzić `main` do parsowania argumentu i mapowania błędu na kod wyjścia.
Rozpoznaje ukrytą komendę `__test-filter` (oraz jej wariant wymuszający awarię) i nic więcej.

**Kontrakt**: `git-crypt __test-filter` czyta `stdin`, pisze przetworzone bajty na `stdout`,
kończy się kodem `0`. `git-crypt __test-filter --fail` nie pisze nic na `stdout` i kończy się
ustalonym niezerowym kodem. Każde inne wywołanie kończy się niezerowym kodem i komunikatem
na `stderr`. Parsowanie przez `std::env::args_os` — bez biblioteki do argumentów, bo pełne
CLI projektuje `S-01`.

### Success Criteria:

#### Automated Verification:

- Projekt buduje się z obydwoma celami: `cargo build`
- Transformacja działa i jest odwracalna: `printf 'abc' | ./target/debug/git-crypt __test-filter` daje `cba`
- Wariant awaryjny zwraca niezerowy kod: `printf 'abc' | ./target/debug/git-crypt __test-filter --fail; echo $?`
- Testy jednostkowe biblioteki przechodzą: `cargo test --lib`
- Linting przechodzi: `cargo clippy --all-targets -- -D warnings`
- Formatowanie zgodne: `cargo fmt --check`

#### Manual Verification:

- `git-crypt __test-filter` nie wypisuje niczego poza danymi na `stdout` — sprawdzone
  przekierowaniem `stdout` do pliku i porównaniem rozmiaru z wejściem.

---

## Phase 2: Harness — repository, filter registration, blob read

### Overview

Pionowy przekrój: od utworzenia repozytorium do odczytania bajtów, które git faktycznie zapisał.

### Changes Required:

#### 1. Moduł harnessu

**Plik**: `tests/harness/mod.rs`

**Cel**: dostarczyć fabrykę repozytorium testowego i operacje potrzebne do zbudowania
dowodu. Katalog `tests/harness/` nie jest osobnym celem testowym — pliki testów dołączają
go przez `mod harness;`.

**Kontrakt**: typ reprezentujący repozytorium testowe, trzymający `tempfile::TempDir`
(sprzątanie przy porzuceniu) i ścieżkę roboczą, z operacjami:

- utworzenie repozytorium: `git init` + lokalne `user.name` i `user.email`.
  **Świadomie nie izolujemy globalnej konfiguracji gita** — decyzja użytkownika, konsekwencje
  w Open Risks.
- rejestracja filtra pod podaną nazwą: ustawia `clean`, `smudge` **oraz `required = true`**;
  polecenie to zacytowana ścieżka `env!("CARGO_BIN_EXE_git-crypt")` z argumentem `__test-filter`.
- zapis pliku z bajtów, zapis `.gitattributes`, uruchomienie dowolnego polecenia gita
  ze zwrotem pełnego `Output`, wykonanie commita.
- odczyt bloba: `git cat-file blob HEAD:<ścieżka>` ze zwrotem `Vec<u8>`.
- odczyt pliku roboczego jako `Vec<u8>`.

Brak `git` w `PATH` kończy się jawnym `panic!` z czytelnym komunikatem — git jest twardym
wymaganiem tych testów, więc ciche pominięcie ukryłoby brak pokrycia.

**Kontrakt cytowania** — jedyny fragment w planie, bo jest nieoczywisty i przenosi ryzyko
przenośności: wartość wpisywana do `filter.<nazwa>.clean` ma postać `"<ścieżka>" __test-filter`,
gdzie w ścieżce separatory `\` są zamieniane na `/`. Git na Windows akceptuje ukośniki
w przód, a `\` w wartości konfiguracji podlega interpretacji jako sekwencja ucieczki.

#### 2. Pierwszy test dowodowy

**Plik**: `tests/filter_pipeline.rs`

**Cel**: udowodnić, że mechanizm w ogóle działa — że zarejestrowany filtr zostaje
uruchomiony przez gita i że treść w obiekcie różni się od treści w katalogu roboczym.

**Kontrakt**: test dołącza `mod harness;`, tworzy repozytorium, rejestruje filtr,
zapisuje plik objęty wzorcem w `.gitattributes` (z `-text`, zgodnie z `zalozenia.md`
§Integracja z git), commituje i sprawdza, że bajty bloba różnią się od bajtów pliku
roboczego oraz że są równe oczekiwanej transformacji.

Drugi test w tym samym pliku sprawdza stronę odwrotną: plik **spoza** wzorca ląduje
w obiekcie gita bez zmian. Bez niego pierwszy test przechodziłby również wtedy, gdyby
filtr działał na wszystkim, a nie tylko na ścieżkach objętych wzorcem.

### Success Criteria:

#### Automated Verification:

- Test pionowego przekroju przechodzi: `cargo test --test filter_pipeline`
- Cały zestaw przechodzi: `cargo test`
- Linting obejmuje testy: `cargo clippy --all-targets -- -D warnings`
- Formatowanie zgodne: `cargo fmt --check`

#### Manual Verification:

- Świadome zepsucie transformacji w `src/lib.rs` (zwrot wejścia bez zmian) powoduje
  **czerwony** test — dowód, że test faktycznie coś sprawdza, a nie przechodzi z rozpędu.
- Katalog tymczasowy znika po zakończeniu testów — `ls` w systemowym katalogu tymczasowym
  nie pokazuje pozostałości.

---

## Phase 3: Clone, assertion layer, edge cases

### Overview

Harness zyskuje drugie repozytorium i cienką warstwę asercji, a zestaw testów pokrywa
przypadki, które w `S-01` będą decydować o poprawności formatu.

### Changes Required:

#### 1. Klon

**Plik**: `tests/harness/mod.rs`

**Cel**: umożliwić scenariusz „druga maszyna" z `prd.md` US-01 — klon repozytorium do
osobnego katalogu tymczasowego, **bez** skonfigurowanego filtra.

**Kontrakt**: operacja zwracająca nowe repozytorium testowe utworzone przez `git clone`
ze ścieżki źródłowego. Klon dziedziczy `.gitattributes` z historii, ale nie dziedziczy
`.git/config` źródła, więc filtr nie jest w nim zarejestrowany — to jest właśnie
stan, który ma być sprawdzany.

#### 2. Warstwa asercji

**Plik**: `tests/harness/mod.rs`

**Cel**: skrócić testy o powtarzalny szablon, nie zamykając drogi do surowych bajtów.

**Kontrakt**: trzy asercje nad bajtami — „blob różni się od pliku roboczego",
„plik roboczy jest bajt w bajt równy podanej treści", „`git status --porcelain` jest pusty".
Każda przy niepowodzeniu wypisuje długości i rozbieżne pozycje, nie całe bufory —
bufor binarny w komunikacie błędu jest nieczytelny.

#### 3. Testy przypadków brzegowych

**Plik**: `tests/filter_edge_cases.rs`

**Cel**: pokryć przypadki, na których `S-01` się wywróci, jeśli nie będą pilnowane od początku.

**Kontrakt**: sześć testów —

1. **checkout odtwarza treść**: usunięcie pliku roboczego i `git checkout --` daje treść
   bajt w bajt równą oryginałowi, a `git status` jest czysty (dowód determinizmu w kształcie
   z `prd.md` §Success Criteria pkt 6),
2. **klon bez filtra**: plik roboczy w klonie równy bajtom bloba, `git clone` kończy się kodem 0,
3. **plik pusty**: przechodzi cykl bez błędu i bez zmiany (asercja o różnicy blob/plik roboczy
   **nie obowiązuje** dla pustego wejścia — transformacja pustego ciągu daje pusty ciąg),
4. **plik binarny**: treść zawierająca wszystkie wartości bajtów `0x00..=0xFF`, w tym sekwencje
   niepoprawne w UTF-8, wraca bez zniekształcenia,
5. **awaria filtra przerywa operację**: filtr zarejestrowany z wariantem `--fail`
   i `required = true` — `git add` kończy się **niezerowym kodem**, a `git ls-files --stage`
   dla tej ścieżki jest **pusty**,
6. **plaintext nie wycieka przy awarii**: po nieudanym `git add` w bazie obiektów nie istnieje
   blob o treści jawnej — hash treści jawnej liczy `git hash-object -t blob --stdin`, a jego
   obecność sprawdza `git cat-file -e`. Treść idzie przez stdin, nie przez plik pomocniczy:
   zapisanie poszukiwanego plaintextu do drzewa roboczego, choćby na moment, stawiałoby go
   o jedno `git add -A` od commita, którego ten test zabrania.

### Success Criteria:

#### Automated Verification:

- Wszystkie przypadki brzegowe przechodzą: `cargo test --test filter_edge_cases`
- Cały zestaw przechodzi: `cargo test`
- Linting przechodzi: `cargo clippy --all-targets -- -D warnings`
- Formatowanie zgodne: `cargo fmt --check`
- Audyt bez znalezisk po dodaniu zależności: `cargo audit`

#### Manual Verification:

- Usunięcie `required = true` z rejestracji filtra powoduje **czerwony** test nr 5 —
  dowód, że test pilnuje właśnie tej flagi, a nie czegoś obok.
- Uruchomienie `cargo test` na drugiej platformie, jeśli jest pod ręką (Linux lub Windows) —
  wynik odnotowany, ale nie blokuje zamknięcia elementu; empiryczna weryfikacja trzech
  platform należy do `S-07`.

---

## Testing Strategy

### Unit tests:

- Odwracalność transformacji: `transform(transform(x)) == x` dla wejścia pustego, jednobajtowego
  i binarnego.
- Determinizm: dwukrotne wywołanie na tym samym wejściu daje identyczne wyjście.

### Integration tests:

- Pełny cykl `add` → `commit` → odczyt bloba → `checkout` → porównanie, na prawdziwym repozytorium.
- Klon do drugiego katalogu i sprawdzenie treści bez klucza (tu: bez filtra).
- Awaria filtra i dowód, że plaintext nie trafił do indeksu ani do bazy obiektów.

### Manual testing steps:

1. `cargo test` — cały zestaw zielony.
2. Zepsuć transformację w `src/lib.rs`, uruchomić `cargo test` — testy 1 i 2 czerwone.
3. Przywrócić transformację, usunąć `required = true` z harnessu, uruchomić `cargo test` —
   test 5 czerwony.
4. Przywrócić `required = true`, potwierdzić zieleń.

## Performance Considerations

Brak. Harness buforuje całe pliki w pamięci, ale pliki testowe są rzędu kilobajtów.
Próg przejścia na buforowanie dyskowe (`prd.md` §Open Questions / `zalozenia.md` §Kryptografia)
dotyczy `S-01`, nie tego elementu.

## Migration Notes

Nie dotyczy — brak istniejących danych i brak wydanego formatu.

## Open Risks and Assumptions

- **Globalna konfiguracja gita nie jest izolowana** (świadoma decyzja użytkownika przy planowaniu).
  Konsekwencja: `core.autocrlf`, globalny `.gitattributes`, szablony hooków i `init.templateDir`
  z maszyny dewelopera lub runnera CI wpływają na wynik testów. Najbardziej prawdopodobny objaw:
  test determinizmu z `S-01` przechodzi u jednej osoby i pada u drugiej, a przyczyna wygląda
  jak regresja szyfrowania. Jeśli to wystąpi, najtańszą osłoną jest ustawienie
  `GIT_CONFIG_GLOBAL` i `GIT_CONFIG_SYSTEM` na ścieżkę nieistniejącą przy każdym wywołaniu gita.

  **Aktualizacja 2026-08-04 — przesłanka tej decyzji się zmieniła.** `zalozenia.md` §Końce linii
  ustala, że smudge **czyta konfigurację gita** (`core.autocrlf`, `core.eol`) przez `gix-config`.
  W momencie podejmowania decyzji jedynym kanałem wycieku była konwersja wykonywana przez samego
  gita, przed którą `-text` chroni — i chroni skutecznie: cały zestaw testów przechodzi przy
  globalnym `core.autocrlf=true` (zweryfikowane). Ale `-text` nie chroni przed **naszymi własnymi
  odczytami konfiguracji**: w `S-01` binarka uruchomiona jako smudge sięgnie po `~/.gitconfig`
  dewelopera, więc wynik `unlock` stanie się zależny od maszyny **z założenia projektu**, a nie
  przez przypadek.

  **Decyzja potwierdzona po zmianie przesłanki (2026-08-04): dziedziczenie zostaje.** Uzasadnienie
  przemawiające za nim: testy odzwierciedlają środowisko, które użytkownik faktycznie ma, więc
  realny błąd konfiguracji wyjdzie w teście, zamiast zostać zamaskowany. Przyjęta konsekwencja:
  testy round-tripu w `S-01` nie są odtwarzalne między maszynami z samego harnessu. Każdy test
  `S-01` zależny od końców linii musi więc **sam** ustawić `core.autocrlf` i `core.eol` lokalnie
  w repozytorium testowym — inaczej jego wynik opisuje maszynę, a nie kod. Pytanie jest zamknięte;
  nie otwierać go ponownie przy planowaniu `S-01`.
- **`zalozenia.md` §Integracja z git zawiera nieprawdziwe zdanie** o przerywaniu operacji przy
  niezerowym kodzie filtra — jest prawdziwe wyłącznie z `required = true`. Dokument fundamentowy
  nie jest poprawiany w tym elemencie; poprawka to osobna praca przed `S-01`.
- **`__test-filter` to kod testowy w binarce produkcyjnej.** Dopóki nie ma pomocy CLI, nie ma
  czego przed czym ukrywać, ale `S-01` musi tę komendę usunąć albo zamknąć za flagą kompilacji —
  inaczej wydana binarka wystawi transformację, która wygląda jak szyfrowanie, a nim nie jest.
- **Przenośność jest zadeklarowana, nie dowiedziona.** Cytowanie ścieżki filtra i zamiana
  separatorów są napisane pod Windows, ale sprawdzone wyłącznie na macOS.

## References

- Roadmapa: `context/foundation/roadmap.md` → `F-01`
- Gwarantki: `context/foundation/prd.md` §Success Criteria → Guardrails
- Reguły filtrów i CI: `context/foundation/zalozenia.md` §Integracja z git, §Jakość i testy
- Stan wyjściowy: `context/changes/bootstrap-verification/verification.md`

## Progress

> Konwencja: `- [ ]` oczekujące, `- [x]` wykonane. Dołącz ` — <commit sha>` po zakończeniu kroku.
> Nie zmieniaj nazw tytułów kroków.

### Phase 1: Crate split and the `__test-filter` command

#### Automated

- [x] 1.1 Projekt buduje się z obydwoma celami: `cargo build`
- [x] 1.2 Transformacja działa i jest odwracalna: `printf 'abc' | ./target/debug/git-crypt __test-filter` daje `cba`
- [x] 1.3 Wariant awaryjny zwraca niezerowy kod — `exit=70`, `stdout` pusty
- [x] 1.4 Testy jednostkowe biblioteki przechodzą: `cargo test --lib` (4 testy)
- [x] 1.5 Linting przechodzi: `cargo clippy --all-targets -- -D warnings`
- [x] 1.6 Formatowanie zgodne: `cargo fmt --check`

#### Manual

- [x] 1.7 `__test-filter` nie wypisuje niczego poza danymi na `stdout` — 4096 losowych bajtów
      wchodzi, 4096 wychodzi, round-trip bajt w bajt

### Phase 2: Harness — repository, filter registration, blob read

#### Automated

- [x] 2.1 Test pionowego przekroju przechodzi: `cargo test --test filter_pipeline` (2 testy)
- [x] 2.2 Cały zestaw przechodzi: `cargo test`
- [x] 2.3 Linting obejmuje testy: `cargo clippy --all-targets -- -D warnings`
- [x] 2.4 Formatowanie zgodne: `cargo fmt --check`

#### Manual

- [x] 2.5 Świadome zepsucie transformacji daje czerwony test — transformacja tożsamościowa
      wywala `committed_blob_differs_from_the_working_tree`
- [x] 2.6 Katalog tymczasowy znika po zakończeniu testów — zero pozostałości w `$TMPDIR`

### Phase 3: Clone, assertion layer, edge cases

#### Automated

- [x] 3.1 Przypadki brzegowe przechodzą: `cargo test --test filter_edge_cases` (6 testów)
- [x] 3.2 Cały zestaw przechodzi: `cargo test` (12 testów, 0 niepowodzeń)
- [x] 3.3 Linting przechodzi: `cargo clippy --all-targets -- -D warnings`
- [x] 3.4 Formatowanie zgodne: `cargo fmt --check`
- [x] 3.5 Audyt bez znalezisk: `cargo audit` — 20 zależności, kod wyjścia 0

#### Manual

- [x] 3.6 Usunięcie `required = true` daje czerwony test awarii filtra — padają **oba** testy,
      nr 5 i nr 6; nr 6 dowodzi, że bez flagi plaintext trafia do bazy obiektów
- [ ] 3.7 `cargo test` na drugiej platformie (opcjonalne, nie blokuje) — niewykonane,
      dostępny wyłącznie macOS
